# ─────────────────────────────────────────────────────────────────
#  Network Intrusion Detection System — Dash Dashboard
#  app.py  |  place in root of network-ids/ folder
#  Run  :  python app.py          (as Administrator on Windows)
#  Open :  http://localhost:8050
#
#  Windows-compatible:
#    • tshark / Npcap for packet capture  (no WinDump / WinPcap)
#    • pure-Python CIC feature extractor  (no CICFlowMeter / Java)
#
#  pip install pyshark dash dash-bootstrap-components plotly
#              joblib shap matplotlib pandas numpy
# ─────────────────────────────────────────────────────────────────
import os, io as _io, base64, warnings, platform
import threading, subprocess, queue, time
import asyncio
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shape
from pathlib import Path
warnings.filterwarnings('ignore')
import dash
from dash import dcc, html, Input, Output, State, dash_table, ctx
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
# ══════════════════════════════════════════════════════════════════
#  1.  PATHS / RUNTIME CONFIG
# ══════════════════════════════════════════════════════════════════
CAPTURE_SECONDS = 10
CONFIDENCE_THRESHOLD = 0.75  # 75% confidence = CONFIRMED, below = SUSPICIOUS
LIVE_TABLE_MAX_ROWS = 500
LIVE_TABLE_LOG_CSV = Path('data/processed/live_cycle_rows_log.csv')
if platform.system() == 'Windows':
    DEFAULT_IFACE = "3"
    TMP_PCAP = r"C:\Temp\live_capture.pcap"
else:
    DEFAULT_IFACE = "lo"
    TMP_PCAP = "/tmp/live_capture.pcap"

# ══════════════════════════════════════════════════════════════════
#  Network Interface Detection & Validation
# ══════════════════════════════════════════════════════════════════
def _get_available_interfaces():
    """List all interfaces available to tshark."""
    try:
        result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return []
        interfaces = []
        for line in result.stdout.split('\n'):
            if line.strip() and '.' in line:
                parts = line.split('. ')
                if len(parts) >= 2:
                    idx = parts[0].strip()
                    name = parts[1].split('(')[0].strip() if '(' in parts[1] else parts[1].strip()
                    interfaces.append((idx, name))
        return interfaces
    except Exception as e:
        print(f"[IfaceDetect] Error listing interfaces: {e}")
        return []

def _test_capture(iface, duration=2, test_pcap=None):
    """Test if an interface can capture packets. Returns (success, packet_count)."""
    if test_pcap is None:
        test_pcap = TMP_PCAP.replace('.pcap', '_test.pcap')
    Path(test_pcap).parent.mkdir(parents=True, exist_ok=True)
    try:
        Path(test_pcap).unlink(missing_ok=True)
    except:
        pass
    try:
        cmd = ['tshark', '-i', iface, '-a', f'duration:{duration}',
               '-w', test_pcap, '-F', 'pcap']
        subprocess.run(cmd, capture_output=True, timeout=duration + 10)
        if Path(test_pcap).exists():
            size = Path(test_pcap).stat().st_size
            try:
                Path(test_pcap).unlink()
            except:
                pass
            return (size > 100, size)
        return (False, 0)
    except Exception as e:
        print(f"[IfaceDetect] Capture test failed on {iface}: {e}")
        return (False, 0)

def _detect_active_interface():
    """Auto-detect the active network interface (with traffic/gateway)."""
    interfaces = _get_available_interfaces()
    if not interfaces:
        return None, "No interfaces found. Run: tshark -D"
    print("[IfaceDetect] Available interfaces:")
    for idx, name in interfaces:
        print(f"  {idx}. {name}")
    print("[IfaceDetect] Testing interfaces for active traffic...")
    for idx, name in interfaces:
        if any(x in name.lower() for x in ['loopback', 'lo0', 'npcap']):
            continue
        success, pkt_count = _test_capture(idx, duration=2)
        if success:
            print(f"[IfaceDetect] ✓ Interface {idx} ({name}) has traffic ({pkt_count} bytes)")
            return idx, name
        else:
            print(f"[IfaceDetect] ✗ Interface {idx} ({name}) - no traffic")
    for idx, name in interfaces:
        if 'loopback' not in name.lower() and 'lo0' not in name.lower():
            print(f"[IfaceDetect] No active interface found. Falling back to {idx} ({name})")
            return idx, name
    if interfaces:
        print(f"[IfaceDetect] Using fallback {interfaces[0][0]} ({interfaces[0][1]})")
        return interfaces[0]
    return None, "No suitable interfaces detected"

AUTO_DETECTED_IFACE, AUTO_DETECTED_NAME = _detect_active_interface()
if AUTO_DETECTED_IFACE:
    DEFAULT_IFACE = AUTO_DETECTED_IFACE
    print(f"[IfaceDetect] Auto-selected: {DEFAULT_IFACE} ({AUTO_DETECTED_NAME})")
else:
    print(f"[IfaceDetect] WARNING: {AUTO_DETECTED_NAME}")
# ══════════════════════════════════════════════════════════════════
#  2.  LOAD MODELS & ARTEFACTS
# ══════════════════════════════════════════════════════════════════
print("Loading models ...")
rf = joblib.load('models/random_forest.pkl')
le = joblib.load('models/label_encoder.pkl')
scaler = joblib.load('models/scaler.pkl')
feat_names = joblib.load('models/feature_names.pkl')
shap_vals = joblib.load('models/shap_values.pkl')
explainer = joblib.load('models/shap_explainer.pkl')
X_test = joblib.load('data/processed/X_test.pkl')
y_test = joblib.load('data/processed/y_test.pkl')
CLASS_NAMES = []
for c in le.classes_:
    clean = c.replace('\ufffd', '-').replace('ae"', '-').replace('a', '-')
    clean = ''.join(ch if ord(ch) < 128 else '-' for ch in clean)
    clean = clean.strip('- ').replace('--', '-')
    CLASS_NAMES.append(clean)
BENIGN_IDX = list(le.classes_).index('BENIGN')
ATTACK_COLOUR = '#FF4444'
BENIGN_COLOUR = '#00FF88'
# ══════════════════════════════════════════════════════════════════
#  Attack Information Database (hardcoded descriptions)
# ══════════════════════════════════════════════════════════════════
ATTACK_INFO = {
    'BENIGN': {
        'severity': 'SAFE',
        'description': 'Normal network traffic. No malicious activity detected.',
        'color': '#00FF88',
        'type': 'Normal'
    },
    'Bot': {
        'severity': 'CRITICAL',
        'description': 'Botnet malware infection detected. System may be compromised and controlled remotely.',
        'color': '#FF4444',
        'type': 'Malware'
    },
    'DDoS': {
        'severity': 'CRITICAL',
        'description': 'Distributed Denial of Service attack. Massive traffic flood from multiple sources.',
        'color': '#FF4444',
        'type': 'Attack'
    },
    'DoS-GoldenEye': {
        'severity': 'HIGH',
        'description': 'GoldenEye DoS attack. Application-layer HTTP flooding attack targeting web servers.',
        'color': '#FF6644',
        'type': 'Attack'
    },
    'DoS-Hulk': {
        'severity': 'HIGH',
        'description': 'Hulk DoS attack. High-speed HTTP GET/POST flooding against web applications.',
        'color': '#FF6644',
        'type': 'Attack'
    },
    'DoS-Slowhttptest': {
        'severity': 'MEDIUM',
        'description': 'Slowhttptest attack. Sends partial HTTP requests very slowly to exhaust server resources.',
        'color': '#FFAA00',
        'type': 'Attack'
    },
    'DoS-slowloris': {
        'severity': 'MEDIUM',
        'description': 'Slowloris attack. Keeps HTTP connections open as long as possible to starve server resources.',
        'color': '#FFAA00',
        'type': 'Attack'
    },
    'FTP-Patator': {
        'severity': 'HIGH',
        'description': 'FTP brute-force attack. Rapid login attempts using dictionary/password lists.',
        'color': '#FF6644',
        'type': 'Brute Force'
    },
    'Heartbleed': {
        'severity': 'CRITICAL',
        'description': 'Heartbleed vulnerability exploitation (OpenSSL). Server memory leak attack. May be false positive on benign HTTPS traffic.',
        'color': '#FF4444',
        'type': 'Vulnerability'
    },
    'Infiltration': {
        'severity': 'CRITICAL',
        'description': 'Data exfiltration attempt detected. Sensitive data being extracted from network.',
        'color': '#FF4444',
        'type': 'Data Theft'
    },
    'PortScan': {
        'severity': 'MEDIUM',
        'description': 'Network port scanning activity. System is probing network for open ports and services.',
        'color': '#FFAA00',
        'type': 'Reconnaissance'
    },
    'SSH-Patator': {
        'severity': 'HIGH',
        'description': 'SSH brute-force attack. Rapid login attempts on SSH service.',
        'color': '#FF6644',
        'type': 'Brute Force'
    },
    'Web-BruteForce': {
        'severity': 'HIGH',
        'description': 'Web application brute-force attack. Multiple login failures on web service.',
        'color': '#FF6644',
        'type': 'Brute Force'
    },
    'Web-SqlInjection': {
        'severity': 'CRITICAL',
        'description': 'SQL injection attack detected. Attacker attempting to execute malicious SQL queries.',
        'color': '#FF4444',
        'type': 'Web Attack'
    },
    'Web-XSS': {
        'severity': 'HIGH',
        'description': 'Cross-Site Scripting (XSS) attack. Malicious script injection in web traffic.',
        'color': '#FF6644',
        'type': 'Web Attack'
    },
}

def idx_to_name(idx):
    try:
        return CLASS_NAMES[idx]
    except:
        return str(idx)

def get_attack_info(class_name):
    """Get attack info by clean class name."""
    for key, info in ATTACK_INFO.items():
        if key.lower().replace('-', '').replace(' ', '') == class_name.lower().replace('-', '').replace(' ', ''):
            return info
    return ATTACK_INFO.get('BENIGN')

print(f"Classes : {CLASS_NAMES}")
print(f"Features: {len(feat_names)}")
print(f"Platform: {platform.system()}")
print("Models loaded - starting app ...")
# ══════════════════════════════════════════════════════════════════
#  3.  PRECOMPUTE GLOBAL SHAP
# ══════════════════════════════════════════════════════════════════
mean_abs_shap = np.abs(shap_vals).mean(axis=0).mean(axis=1)
shap_rank = np.argsort(mean_abs_shap)[::-1]
shap_sorted_vals = mean_abs_shap[shap_rank]
shap_sorted_feats = [feat_names[i] for i in shap_rank]

# ══════════════════════════════════════════════════════════════════
#  4.  PURE-PYTHON CIC FEATURE EXTRACTOR
# ══════════════════════════════════════════════════════════════════
def _safe_div(a, b, default=0.0):
    return a / b if b else default

def _stats(lst):
    if not lst:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(lst, dtype=np.float64)
    return float(a.mean()), float(a.std()), float(a.max()), float(a.min())

def _iat_list(timestamps):
    if len(timestamps) < 2:
        return []
    return [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

class _Flow:
    __slots__ = [
        'key', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'start_ts', 'last_ts',
        'fwd_pkts', 'bwd_pkts',
        'fwd_lens', 'bwd_lens',
        'fwd_ts', 'bwd_ts',
        'fwd_hdr_lens', 'bwd_hdr_lens',
        'fwd_flags', 'bwd_flags',
        'all_ts',
        'init_win_fwd', 'init_win_bwd',
        'fwd_act_data', 'bwd_act_data',
    ]
    def __init__(self, key, src_ip, dst_ip, src_port, dst_port, protocol, ts):
        self.key = key
        self.src_ip = src_ip;
        self.dst_ip = dst_ip
        self.src_port = src_port;
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_ts = ts;
        self.last_ts = ts
        self.fwd_pkts = [];
        self.bwd_pkts = []
        self.fwd_lens = [];
        self.bwd_lens = []
        self.fwd_ts = [];
        self.bwd_ts = []
        self.fwd_hdr_lens = [];
        self.bwd_hdr_lens = []
        self.fwd_flags = [];
        self.bwd_flags = []
        self.all_ts = [ts]
        self.init_win_fwd = 0;
        self.init_win_bwd = 0
        self.fwd_act_data = [];
        self.bwd_act_data = []

def _extract_packet_fields(pkt):
    try:
        ts = float(pkt.sniff_timestamp)
        src_ip = dst_ip = ''
        src_port = dst_port = pkt_len = hdr_len = flags = window = payload = 0
        proto = 0
        if hasattr(pkt, 'ip'):
            src_ip = pkt.ip.src;
            dst_ip = pkt.ip.dst
            pkt_len = int(pkt.ip.len)
        elif hasattr(pkt, 'ipv6'):
            src_ip = pkt.ipv6.src;
            dst_ip = pkt.ipv6.dst
            pkt_len = int(pkt.ipv6.plen)
        else:
            return None
        if hasattr(pkt, 'tcp'):
            proto = 6
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
            hdr_len = int(pkt.tcp.hdr_len)
            try:
                flags = int(pkt.tcp.flags, 16)
            except:
                flags = 0
            try:
                window = int(pkt.tcp.window_size_value)
            except:
                window = 0
            try:
                payload = int(pkt.tcp.len)
            except:
                payload = max(0, pkt_len - hdr_len)
        elif hasattr(pkt, 'udp'):
            proto = 17
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)
            hdr_len = 8
            try:
                payload = int(pkt.udp.length) - 8
            except:
                payload = 0
        else:
            return None
        return dict(ts=ts, src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    proto=proto, pkt_len=pkt_len, hdr_len=hdr_len,
                    flags=flags, window=window, payload=max(0, payload))
    except Exception:
        return None

def _compute_cic_features(flow):
    duration = max(flow.last_ts - flow.start_ts, 1e-6)
    fwd_n = len(flow.fwd_lens);
    bwd_n = len(flow.bwd_lens);
    tot_n = fwd_n + bwd_n
    fwd_mean, fwd_std, fwd_max, fwd_min = _stats(flow.fwd_lens)
    bwd_mean, bwd_std, bwd_max, bwd_min = _stats(flow.bwd_lens)
    all_mean, all_std, all_max, all_min = _stats(flow.fwd_lens + flow.bwd_lens)
    fwd_bytes = sum(flow.fwd_lens);
    bwd_bytes = sum(flow.bwd_lens)
    tot_bytes = fwd_bytes + bwd_bytes
    fwd_iat = _iat_list(sorted(flow.fwd_ts))
    bwd_iat = _iat_list(sorted(flow.bwd_ts))
    flow_iat = _iat_list(sorted(flow.all_ts))
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(fwd_iat)
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(bwd_iat)
    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _stats(flow_iat)
    def _fc(fl, mask): return sum(1 for f in fl if f & mask)
    FIN = 0x01;
    SYN = 0x02;
    RST = 0x04;
    PSH = 0x08
    ACK = 0x10;
    URG = 0x20;
    ECE = 0x40;
    CWR = 0x80
    af = flow.fwd_flags + flow.bwd_flags
    fwd_act_m, _, _, _ = _stats(flow.fwd_act_data)
    bwd_act_m, _, _, _ = _stats(flow.bwd_act_data)
    return {
        ' Destination Port': float(flow.dst_port),
        ' Flow Duration': duration * 1e6,
        ' Total Fwd Packets': float(fwd_n),
        ' Total Backward Packets': float(bwd_n),
        ' Total Length of Fwd Packets': float(fwd_bytes),
        ' Total Length of Bwd Packets': float(bwd_bytes),
        ' Fwd Packet Length Max': fwd_max,
        ' Fwd Packet Length Min': fwd_min,
        ' Fwd Packet Length Mean': fwd_mean,
        ' Fwd Packet Length Std': fwd_std,
        'Bwd Packet Length Max': bwd_max,
        'Bwd Packet Length Min': bwd_min,
        'Bwd Packet Length Mean': bwd_mean,
        'Bwd Packet Length Std': bwd_std,
        'Flow Bytes/s': _safe_div(tot_bytes, duration),
        ' Flow Packets/s': _safe_div(tot_n, duration),
        ' Flow IAT Mean': flow_iat_mean * 1e6,
        ' Flow IAT Std': flow_iat_std * 1e6,
        ' Flow IAT Max': flow_iat_max * 1e6,
        ' Flow IAT Min': flow_iat_min * 1e6,
        'Fwd IAT Total': sum(fwd_iat) * 1e6,
        ' Fwd IAT Mean': fwd_iat_mean * 1e6,
        ' Fwd IAT Std': fwd_iat_std * 1e6,
        ' Fwd IAT Max': fwd_iat_max * 1e6,
        ' Fwd IAT Min': fwd_iat_min * 1e6,
        'Bwd IAT Total': sum(bwd_iat) * 1e6,
        ' Bwd IAT Mean': bwd_iat_mean * 1e6,
        ' Bwd IAT Std': bwd_iat_std * 1e6,
        ' Bwd IAT Max': bwd_iat_max * 1e6,
        ' Bwd IAT Min': bwd_iat_min * 1e6,
        'Fwd PSH Flags': float(_fc(flow.fwd_flags, PSH)),
        ' Bwd PSH Flags': float(_fc(flow.bwd_flags, PSH)),
        ' Fwd URG Flags': float(_fc(flow.fwd_flags, URG)),
        ' Bwd URG Flags': float(_fc(flow.bwd_flags, URG)),
        ' Fwd Header Length': float(sum(flow.fwd_hdr_lens)),
        ' Bwd Header Length': float(sum(flow.bwd_hdr_lens)),
        'Fwd Packets/s': _safe_div(fwd_n, duration),
        ' Bwd Packets/s': _safe_div(bwd_n, duration),
        ' Min Packet Length': all_min,
        ' Max Packet Length': all_max,
        ' Packet Length Mean': all_mean,
        ' Packet Length Std': all_std,
        ' Packet Length Variance': all_std ** 2,
        'FIN Flag Count': float(_fc(af, FIN)),
        ' SYN Flag Count': float(_fc(af, SYN)),
        ' RST Flag Count': float(_fc(af, RST)),
        ' PSH Flag Count': float(_fc(af, PSH)),
        ' ACK Flag Count': float(_fc(af, ACK)),
        ' URG Flag Count': float(_fc(af, URG)),
        ' CWE Flag Count': float(_fc(af, CWR)),
        ' ECE Flag Count': float(_fc(af, ECE)),
        ' Down/Up Ratio': _safe_div(bwd_bytes, fwd_bytes),
        ' Average Packet Size': _safe_div(tot_bytes, tot_n),
        ' Avg Fwd Segment Size': fwd_mean,
        ' Avg Bwd Segment Size': bwd_mean,
        ' Fwd Header Length.1': float(sum(flow.fwd_hdr_lens)),
        'Fwd Avg Bytes/Bulk': fwd_act_m,
        ' Fwd Avg Packets/Bulk': float(len(flow.fwd_act_data)),
        ' Fwd Avg Bulk Rate': _safe_div(sum(flow.fwd_act_data), duration),
        ' Bwd Avg Bytes/Bulk': bwd_act_m,
        ' Bwd Avg Packets/Bulk': float(len(flow.bwd_act_data)),
        'Bwd Avg Bulk Rate': _safe_div(sum(flow.bwd_act_data), duration),
        'Subflow Fwd Packets': float(fwd_n),
        ' Subflow Fwd Bytes': float(fwd_bytes),
        ' Subflow Bwd Packets': float(bwd_n),
        ' Subflow Bwd Bytes': float(bwd_bytes),
        'Init_Win_bytes_forward': float(flow.init_win_fwd),
        ' Init_Win_bytes_backward': float(flow.init_win_bwd),
        ' act_data_pkt_fwd': float(len(flow.fwd_act_data)),
        ' min_seg_size_forward': fwd_min,
        'Active Mean': 0.0, ' Active Std': 0.0, ' Active Max': 0.0, ' Active Min': 0.0,
        'Idle Mean': 0.0, ' Idle Std': 0.0, ' Idle Max': 0.0, ' Idle Min': 0.0,
    }

def _build_flows_from_pcap(pcap_path: str) -> pd.DataFrame:
    """Read pcap, group into 5-tuple flows, compute CIC-style features."""
    try:
        import pyshark
    except ImportError:
        print("[FlowExtractor] pyshark not installed. Run: pip install pyshark")
        return pd.DataFrame()
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    FLOW_TIMEOUT = 120.0
    flows = {}
    finished = []
    try:
        cap = pyshark.FileCapture(
            pcap_path,
            display_filter='tcp or udp',
            keep_packets=False,
            use_ek=False,
        )
        for pkt in cap:
            p = _extract_packet_fields(pkt)
            if p is None:
                continue
            fwd_key = (p['src_ip'], p['dst_ip'], p['src_port'], p['dst_port'], p['proto'])
            bwd_key = (p['dst_ip'], p['src_ip'], p['dst_port'], p['src_port'], p['proto'])
            if fwd_key in flows:
                key, direction = fwd_key, 'fwd'
            elif bwd_key in flows:
                key, direction = bwd_key, 'bwd'
            else:
                key, direction = fwd_key, 'fwd'
            if key in flows and p['ts'] - flows[key].last_ts > FLOW_TIMEOUT:
                finished.append(_compute_cic_features(flows[key]))
                del flows[key]
                direction = 'fwd'
            if key not in flows:
                flows[key] = _Flow(key, p['src_ip'], p['dst_ip'],
                                   p['src_port'], p['dst_port'], p['proto'], p['ts'])
            fl = flows[key]
            fl.last_ts = p['ts']
            fl.all_ts.append(p['ts'])
            if direction == 'fwd':
                fl.fwd_lens.append(p['pkt_len'])
                fl.fwd_ts.append(p['ts'])
                fl.fwd_hdr_lens.append(p['hdr_len'])
                fl.fwd_flags.append(p['flags'])
                if p['payload'] > 0: fl.fwd_act_data.append(p['payload'])
                if not fl.fwd_pkts:  fl.init_win_fwd = p['window']
                fl.fwd_pkts.append(1)
            else:
                fl.bwd_lens.append(p['pkt_len'])
                fl.bwd_ts.append(p['ts'])
                fl.bwd_hdr_lens.append(p['hdr_len'])
                fl.bwd_flags.append(p['flags'])
                if p['payload'] > 0: fl.bwd_act_data.append(p['payload'])
                if not fl.bwd_pkts:  fl.init_win_bwd = p['window']
                fl.bwd_pkts.append(1)
        cap.close()
    except Exception as e:
        print(f"[FlowExtractor] Error reading pcap: {e}")
        return pd.DataFrame()
    for fl in flows.values():
        if len(fl.fwd_lens) + len(fl.bwd_lens) > 0:
            finished.append(_compute_cic_features(fl))
    if not finished:
        return pd.DataFrame()
    df = pd.DataFrame(finished)
    df.columns = df.columns.str.strip()
    return df

def _align_to_model(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure DataFrame has exactly the feature columns the model expects."""
    df.columns = df.columns.str.strip()
    result = {}
    for f in feat_names:
        stripped = f.strip()
        if stripped in df.columns:
            result[f] = df[stripped].values
        elif f in df.columns:
            result[f] = df[f].values
        else:
            result[f] = np.zeros(len(df))
    return pd.DataFrame(result)

# ══════════════════════════════════════════════════════════════════
#  5.  LIVE PIPELINE ENGINE
# ══════════════════════════════════════════════════════════════════
result_queue = queue.Queue()
pipeline_flag = threading.Event()
filter_attack = None  # Set when user selects attack type to monitor
INTERFACE = DEFAULT_IFACE

def capture_packets(iface, pcap_path, duration):
    Path(pcap_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        cmd = ['tshark', '-i', iface,
               '-a', f'duration:{duration}',
               '-w', pcap_path, '-F', 'pcap']
        subprocess.run(cmd, capture_output=True, timeout=duration + 20)
        return Path(pcap_path).exists() and Path(pcap_path).stat().st_size > 0
    except subprocess.TimeoutExpired:
        return Path(pcap_path).exists()
    except Exception as e:
        print(f"[Capture] Error: {e}")
        return False

def _classify_flows(flow_df: pd.DataFrame, cycle: int) -> list:
    aligned = _align_to_model(flow_df)
    X_live = np.nan_to_num(
        aligned[feat_names].values.astype('float32'),
        nan=0.0, posinf=0.0, neginf=0.0)
    preds = rf.predict(X_live)
    probs = rf.predict_proba(X_live)
    conf = probs[np.arange(len(preds)), preds]
    ts = time.strftime("%H:%M:%S")
    rows = []
    for i in range(len(preds)):
        pred_name = idx_to_name(preds[i])
        confidence = conf[i]
        # Determine status based on confidence threshold
        if pred_name == 'BENIGN':
            status = 'BENIGN'
            severity = 'SAFE'
        elif confidence >= CONFIDENCE_THRESHOLD:
            status = 'CONFIRMED ATTACK'
            severity = get_attack_info(pred_name).get('severity', 'HIGH')
        else:
            status = 'SUSPICIOUS'
            severity = get_attack_info(pred_name).get('severity', 'MEDIUM')
        # If filtering by attack type, only include matching
        if filter_attack and pred_name != filter_attack:
            continue
        rows.append({
            'type': 'flow',
            'cycle': cycle,
            'flow': i + 1,
            'src_ip': '—',
            'dst_ip': '—',
            'prediction': pred_name,
            'confidence': f"{confidence * 100:.1f}%",
            'status': status,
            'severity': severity,
            'timestamp': ts,
        })
    n_atk = sum(1 for r in rows if r['status'] != 'BENIGN')
    print(f"[Pipeline] Cycle {cycle}: {len(preds)} flows, {n_atk} alerts")
    return rows

def pipeline_worker():
    """Background thread: capture -> extract flows -> classify."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cycle = 0
    while pipeline_flag.is_set():
        cycle += 1
        print(f"[Pipeline] Cycle {cycle} - capturing {CAPTURE_SECONDS}s on {INTERFACE}...")
        captured = capture_packets(INTERFACE, TMP_PCAP, CAPTURE_SECONDS)
        if not captured:
            result_queue.put({
                'type': 'error',
                'msg': f'Capture failed on interface "{INTERFACE}". Run: tshark -D'
            })
            time.sleep(3)
            continue
        flow_df = _build_flows_from_pcap(TMP_PCAP)
        try:
            Path(TMP_PCAP).unlink(missing_ok=True)
        except Exception:
            pass
        if flow_df.empty:
            result_queue.put({
                'type': 'warning',
                'msg': f'Cycle {cycle}: no flows extracted'
            })
            continue
        try:
            for row in _classify_flows(flow_df, cycle):
                result_queue.put(row)
        except Exception as e:
            result_queue.put({'type': 'error', 'msg': f'Classify error: {e}'})
    result_queue.put({'type': 'done', 'msg': 'Pipeline stopped.'})
    print("[Pipeline] Worker exited.")

# ══════════════════════════════════════════════════════════════════
#  6.  HELPERS
# ══════════════════════════════════════════════════════════════════
def _safe_read_csv(contents, filename):
    _, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    raw_str = decoded.decode('utf-8', errors='replace')
    all_cols = pd.read_csv(_io.StringIO(raw_str), nrows=0).columns.str.strip().tolist()
    dtype_map = {c: 'float32' for c in all_cols if c not in ('Label', ' Label')}
    df = pd.read_csv(_io.StringIO(raw_str), dtype=dtype_map, on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    return df

def _append_live_rows_to_log(rows):
    """Append live flow rows to local CSV so the table can be rebuilt reliably."""
    if not rows:
        return
    LIVE_TABLE_LOG_CSV.parent.mkdir(parents=True, exist_ok=True)
    write_header = not LIVE_TABLE_LOG_CSV.exists()
    logged_at = time.strftime('%Y-%m-%d %H:%M:%S')
    out_rows = []
    for r in rows:
        out_rows.append({
            'logged_at': logged_at,
            'cycle': r.get('cycle', '—'),
            'flow': r.get('flow', '—'),
            'timestamp': r.get('timestamp', '—'),
            'prediction': r.get('prediction', '—'),
            'confidence': r.get('confidence', '—'),
            'status': r.get('status', '—'),
            'severity': r.get('severity', '—'),
            'src_ip': r.get('src_ip', '—'),
            'dst_ip': r.get('dst_ip', '—'),
        })
    pd.DataFrame(out_rows).to_csv(
        LIVE_TABLE_LOG_CSV,
        mode='a',
        header=write_header,
        index=False,
        encoding='utf-8'
    )

def _read_recent_live_rows(limit=LIVE_TABLE_MAX_ROWS):
    """Read and return the most recent logged flow rows as UI row dicts."""
    if not LIVE_TABLE_LOG_CSV.exists():
        return []
    try:
        df = pd.read_csv(LIVE_TABLE_LOG_CSV)
    except Exception:
        return []
    if df.empty:
        return []
    # Keep latest rows only; preserves restart behavior and bounds memory/UI size.
    df = df.tail(limit).copy()
    df = df.fillna('—')
    return [{
        'type': 'flow',
        'cycle': row.get('cycle', '—'),
        'flow': row.get('flow', '—'),
        'src_ip': row.get('src_ip', '—'),
        'dst_ip': row.get('dst_ip', '—'),
        'prediction': row.get('prediction', '—'),
        'confidence': row.get('confidence', '—'),
        'status': row.get('status', '—'),
        'severity': row.get('severity', '—'),
        'timestamp': row.get('timestamp', '—'),
    } for _, row in df.iterrows()]

def _render_results(rows, live=False):
    blank = html.Div("No results yet.",
                     style={'color': '#555', 'textAlign': 'center',
                            'padding': '30px', 'fontSize': '13px'})
    if not rows:
        return rows, blank, "—", "—", "—", html.Div(), blank, "", html.Div()
    total = len(rows)
    attacks = sum(1 for r in rows if r['status'] != 'BENIGN')
    benign = total - attacks
    pct = attacks / total * 100 if total > 0 else 0
    if attacks == 0:
        banner = html.Div(
            f"ALL CLEAR  {total:,} flows analysed, 0 attacks",
            style=CSS['safe'])
        last_attack_info = html.Div()
    else:
        last_atk = next((r['prediction'] for r in reversed(rows)
                         if r['status'] != 'BENIGN'), 'Attack')
        info = get_attack_info(last_atk)
        banner = html.Div(
            f"ALERT  {last_atk.upper()}  ({info['severity']})  |  "
            f"{attacks:,} / {total:,} flows  ({pct:.1f}%)"
            + ("  LIVE" if live else ""),
            style=CSS['alert'])
        last_attack_info = html.Div([
            html.Div(f"Latest: {last_atk}",
                     style={'color': '#FF6644', 'fontSize': '11px', 'fontWeight': 'bold',
                            'marginBottom': '6px'}),
            html.Div(info['description'],
                     style={'color': '#ddd', 'fontSize': '10px', 'lineHeight': '1.4',
                            'marginBottom': '6px'}),
            html.Div(f"Severity: {info['severity']} | Type: {info['type']}",
                     style={'color': '#888', 'fontSize': '9px'})
        ], style={**CSS['card'], 'backgroundColor': '#1a0a0a',
                  'borderColor': '#FF6644'})
    counts = {}
    for r in rows:
        counts[r['prediction']] = counts.get(r['prediction'], 0) + 1
    labels_s = sorted(counts, key=counts.get, reverse=True)
    colours = [BENIGN_COLOUR if l == 'BENIGN' else ATTACK_COLOUR for l in labels_s]
    fig = go.Figure(go.Bar(
        x=labels_s, y=[counts[l] for l in labels_s],
        marker_color=colours,
        text=[f"{counts[l]:,}" for l in labels_s],
        textposition='outside',
        textfont=dict(color='#e6edf3', size=11)
    )).update_layout(
        paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
        font_color='#e6edf3', font_size=11,
        margin=dict(l=20, r=20, t=30, b=80),
        xaxis=dict(gridcolor='#30363d', tickangle=30),
        yaxis=dict(gridcolor='#30363d', title='Count'),
        height=240, showlegend=False)
    breakdown = html.Div([
        html.Div("ATTACK TYPE BREAKDOWN",
                 style={'color': '#555', 'fontSize': '11px',
                        'letterSpacing': '1px', 'marginBottom': '4px'}),
        dcc.Graph(figure=fig, config={'displayModeBar': False})
    ])
    display = list(reversed(rows[-LIVE_TABLE_MAX_ROWS:])) if live else rows
    tbl = dash_table.DataTable(
        data=[{
            'Cycle': r.get('cycle', '—'),
            'Flow': r['flow'],
            'Time': r.get('timestamp', '—'),
            'Prediction': r['prediction'],
            'Confidence': r['confidence'],
            'Status': r['status'],
            'Severity': r.get('severity', '—'),
        } for r in display],
        columns=[{'name': c, 'id': c}
                 for c in ['Cycle', 'Flow', 'Time', 'Prediction', 'Confidence', 'Status', 'Severity']],
        page_size=20, filter_action='native', sort_action='native',
        style_table={'overflowX': 'auto'},
        style_cell={
            'backgroundColor': '#0d1117', 'color': '#e6edf3',
            'border': '1px solid #30363d', 'textAlign': 'center',
            'fontFamily': 'Consolas, monospace', 'fontSize': '12px', 'padding': '7px'},
        style_header={
            'backgroundColor': '#161b22', 'color': '#00FF88',
            'fontWeight': 'bold', 'border': '1px solid #30363d'},
        style_data_conditional=[
            {'if': {'filter_query': '{Status} = "CONFIRMED ATTACK"'},
             'backgroundColor': '#1a0000', 'color': '#FF4444', 'fontWeight': 'bold'},
            {'if': {'filter_query': '{Status} = "SUSPICIOUS"'},
             'backgroundColor': '#0a0a00', 'color': '#FFAA00', 'fontWeight': 'bold'},
            {'if': {'filter_query': '{Status} = "BENIGN"'}, 'color': '#00FF88'}
        ])
    rc = f"{total:,} rows" + (" (last 500 shown)" if live and total > 500 else "")
    return (rows, banner, f"{total:,}", f"{attacks:,}", f"{benign:,}",
            breakdown, tbl, rc, last_attack_info)

def _build_model_table():
    try:
        df = pd.read_csv('data/processed/model_comparison.csv')
        return dash_table.DataTable(
            data=df.round(4).to_dict('records'),
            columns=[{'name': c, 'id': c} for c in df.columns],
            style_table={'overflowX': 'auto'},
            style_cell={
                'backgroundColor': '#161b22', 'color': '#e6edf3',
                'border': '1px solid #30363d', 'textAlign': 'center',
                'fontFamily': 'Consolas, monospace', 'fontSize': '13px', 'padding': '10px'},
            style_header={
                'backgroundColor': '#0d1117', 'color': '#00FF88',
                'fontWeight': 'bold', 'border': '1px solid #30363d'},
            style_data_conditional=[{
                'if': {'row_index': 0},
                'backgroundColor': '#003d1a', 'color': '#00FF88', 'fontWeight': 'bold'}])
    except Exception:
        return html.Span("model_comparison.csv not found.",
                         style={'color': '#555', 'fontSize': '13px'})

# ══════════════════════════════════════════════════════════════════
#  7.  STYLES
# ══════════════════════════════════════════════════════════════════
CSS = {
    'card': {'backgroundColor': '#0d1117', 'border': '1px solid #30363d',
             'borderRadius': '8px', 'padding': '14px', 'marginBottom': '14px'},
    'metric': {'backgroundColor': '#161b22', 'border': '1px solid #30363d',
               'borderRadius': '8px', 'padding': '16px', 'textAlign': 'center',
               'marginBottom': '10px'},
    'alert': {'backgroundColor': '#3d0000', 'border': '1px solid #FF4444',
              'borderRadius': '6px', 'padding': '10px', 'color': '#FF4444',
              'fontWeight': 'bold', 'textAlign': 'center', 'fontSize': '13px'},
    'safe': {'backgroundColor': '#003d1a', 'border': '1px solid #00FF88',
             'borderRadius': '6px', 'padding': '10px', 'color': '#00FF88',
             'fontWeight': 'bold', 'textAlign': 'center', 'fontSize': '13px'},
    'idle': {'backgroundColor': '#111', 'border': '1px solid #30363d',
             'borderRadius': '6px', 'padding': '10px', 'color': '#555',
             'fontWeight': 'bold', 'textAlign': 'center', 'fontSize': '13px'},
    'warn': {'backgroundColor': '#2a1a00', 'border': '1px solid #FFAA00',
             'borderRadius': '6px', 'padding': '10px', 'color': '#FFAA00',
             'fontWeight': 'bold', 'textAlign': 'center', 'fontSize': '12px'},
}
# ══════════════════════════════════════════════════════════════════
#  8.  APP INIT
# ══════════════════════════════════════════════════════════════════
app = dash.Dash(__name__,
                external_stylesheets=[dbc.themes.DARKLY],
                suppress_callback_exceptions=True)
app.title = "Network IDS"
# ══════════════════════════════════════════════════════════════════
#  9.  HEADER
# ══════════════════════════════════════════════════════════════════
HEADER = dbc.Navbar(
    dbc.Container([
        html.Div([
            html.Span("NETWORK INTRUSION DETECTION SYSTEM",
                      style={'fontSize': '17px', 'fontWeight': 'bold',
                             'color': '#00FF88', 'letterSpacing': '2px'}),
        ], style={'display': 'flex', 'alignItems': 'center'}),
        html.Div([
            html.Span("LIVE",
                      style={'color': '#00FF88', 'fontSize': '11px',
                             'fontWeight': 'bold', 'marginRight': '16px'}),
            html.Span(f"Random Forest  |  {len(CLASS_NAMES)} classes  |  "
                      f"{len(feat_names)} features  |  {platform.system()}",
                      style={'color': '#666', 'fontSize': '11px'})
        ], style={'display': 'flex', 'alignItems': 'center'})
    ], fluid=True),
    color='#0d1117', dark=True,
    style={'borderBottom': '2px solid #00FF88', 'padding': '8px 0'})
# ══════════════════════════════════════════════════════════════════
#  10.  LAYOUT — MONITOR TAB
# ══════════════════════════════════════════════════════════════════
TAB_MONITOR = html.Div([
    dbc.Row([
        # ── LEFT SIDEBAR ────────────────────────────────────────────
        dbc.Col([
            # Pipeline controls
            html.Div([
                html.Div("LIVE PIPELINE",
                         style={'color': '#00FF88', 'fontSize': '11px',
                                'fontWeight': 'bold', 'letterSpacing': '2px',
                                'marginBottom': '10px'}),
                html.Label("Interface:",
                           style={'color': '#888', 'fontSize': '10px'}),
                dbc.Input(id='iface-input', value=DEFAULT_IFACE, type='text',
                          placeholder='run: tshark -D',
                          style={'backgroundColor': '#161b22', 'color': '#e6edf3',
                                 'border': '1px solid #30363d', 'fontSize': '11px',
                                 'marginBottom': '2px'}),
                html.Div("Windows: run  tshark -D  to find your interface number",
                         style={'color': '#333', 'fontSize': '9px', 'marginBottom': '8px'}),
                html.Label("Capture window (sec):",
                           style={'color': '#888', 'fontSize': '10px'}),
                dbc.Input(id='capture-seconds', value=10, type='number',
                          min=5, max=120,
                          style={'backgroundColor': '#161b22', 'color': '#e6edf3',
                                 'border': '1px solid #30363d', 'fontSize': '11px',
                                 'marginBottom': '10px'}),
                dbc.Row([
                    dbc.Col(dbc.Button("START", id='btn-live-start',
                                       color='success', size='sm',
                                       className='w-100',
                                       style={'fontWeight': 'bold',
                                              'fontSize': '11px'}), width=6),
                    dbc.Col(dbc.Button("STOP", id='btn-live-stop',
                                       color='danger', size='sm',
                                       className='w-100',
                                       style={'fontWeight': 'bold',
                                              'fontSize': '11px'}), width=6),
                ], style={'marginBottom': '8px'}),
                html.Div(id='pipeline-status',
                         children=html.Span(
                             "IDLE",
                             style={'color': '#555', 'fontSize': '10px'}),
                         style={'textAlign': 'center'}),
            ], style=CSS['card']),
            # Metrics
            html.Div([
                html.Div("TOTAL",
                         style={'color': '#888', 'fontSize': '9px', 'letterSpacing': '1px'}),
                html.Div("—", id='sum-total',
                         style={'color': '#e6edf3', 'fontSize': '24px',
                                'fontWeight': 'bold', 'lineHeight': '1.1'}),
            ], style=CSS['metric']),
            html.Div([
                html.Div("ALERTS",
                         style={'color': '#FF4444', 'fontSize': '9px', 'letterSpacing': '1px'}),
                html.Div("—", id='sum-attacks',
                         style={'color': '#FF4444', 'fontSize': '24px',
                                'fontWeight': 'bold', 'lineHeight': '1.1'}),
            ], style=CSS['metric']),
            html.Div([
                html.Div("BENIGN",
                         style={'color': '#00FF88', 'fontSize': '9px', 'letterSpacing': '1px'}),
                html.Div("—", id='sum-benign',
                         style={'color': '#00FF88', 'fontSize': '24px',
                                'fontWeight': 'bold', 'lineHeight': '1.1'}),
            ], style=CSS['metric']),
            # Attack filter (new)
            html.Div([
                html.Div("FILTER ATTACK TYPE",
                         style={'color': '#4a9eff', 'fontSize': '10px',
                                'fontWeight': 'bold', 'letterSpacing': '1px',
                                'marginBottom': '8px'}),
                html.Label("Show only:",
                           style={'color': '#888', 'fontSize': '10px'}),
                dcc.Dropdown(
                    id='attack-filter-dropdown',
                    options=[{'label': 'All Traffic', 'value': None}] +
                            [{'label': n, 'value': n} for n in CLASS_NAMES],
                    value=None, clearable=False,
                    style={'backgroundColor': '#161b22', 'color': '#000',
                           'border': '1px solid #30363d', 'fontSize': '11px',
                           'marginBottom': '6px'}),
                html.Div(id='filter-status',
                         style={'color': '#555', 'fontSize': '9px', 'textAlign': 'center'})
            ], style={**CSS['card'], 'borderColor': '#1a3a5c'}),
            # CSV upload
            html.Div([
                dbc.Button(
                    ["CSV BATCH UPLOAD  ", html.Span("show", id='csv-chevron',
                                                     style={'fontSize': '9px'})],
                    id='csv-toggle-btn', color='secondary', size='sm',
                    style={'backgroundColor': '#0d1117',
                           'border': '1px solid #30363d',
                           'color': '#555', 'fontSize': '10px', 'width': '100%',
                           'textAlign': 'left', 'marginBottom': '4px'}),
                dbc.Collapse(
                    html.Div([
                        html.Div("Upload a CICIDS-format CSV for batch prediction.",
                                 style={'color': '#555', 'fontSize': '9px',
                                        'marginBottom': '6px'}),
                        dcc.Upload(
                            id='upload-csv',
                            children=html.Div(
                                "Drop CSV here or click",
                                style={'textAlign': 'center', 'padding': '10px',
                                       'color': '#00FF88', 'fontSize': '10px'}),
                            style={'border': '1px dashed #00FF88',
                                   'borderRadius': '4px',
                                   'backgroundColor': '#0a0f0a',
                                   'cursor': 'pointer'},
                            accept='.csv'),
                        html.Div(id='upload-status',
                                 style={'color': '#888', 'fontSize': '9px',
                                        'textAlign': 'center', 'marginTop': '4px'}),
                    ], style={'padding': '8px', 'backgroundColor': '#0a0a0a',
                              'border': '1px solid #222', 'borderRadius': '4px'}),
                    id='csv-collapse', is_open=False),
            ]),
        ], width=3),
        # ── MAIN RESULTS AREA ────────────────────────────────────────
        dbc.Col([
            # Status banner
            html.Div(id='analysis-banner',
                     children=html.Div(
                         "Start the pipeline or upload a CSV to begin.",
                         style=CSS['idle']),
                     style={'marginBottom': '10px'}),
            # Attack breakdown chart
            html.Div(id='attack-breakdown-container',
                     style={**CSS['card'], 'minHeight': '60px'}),
            # Latest attack info (new)
            html.Div(id='latest-attack-info',
                     style={'marginBottom': '10px'}),
            # Predictions table
            html.Div([
                html.Div(style={'display': 'flex', 'justifyContent': 'space-between',
                                'alignItems': 'center', 'marginBottom': '8px'},
                         children=[
                             html.Span("FLOW PREDICTIONS",
                                       style={'color': '#666', 'fontSize': '10px',
                                              'letterSpacing': '1px'}),
                             html.Span(id='table-row-count',
                                       style={'color': '#444', 'fontSize': '9px'})
                         ]),
                html.Div(id='results-table-container',
                         children=html.Div(
                             "Results will appear here.",
                             style={'color': '#555', 'fontSize': '11px',
                                    'textAlign': 'center', 'padding': '30px'}))
            ], style=CSS['card']),
        ], width=9),
    ]),
    dcc.Interval(id='live-interval', interval=2000, disabled=True),
    dcc.Store(id='live-rows', data=[]),
    dcc.Store(id='active-filter', data=None),
])
# ══════════════════════════════════════════════════════════════════
#  11.  TAB: MODEL INSIGHTS
# ══════════════════════════════════════════════════════════════════
TAB_INSIGHTS = html.Div([
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H5("Global Feature Importance (SHAP)",
                        style={'color': '#00FF88', 'fontSize': '13px',
                               'letterSpacing': '1px'}),
                html.P("Mean |SHAP| across all predictions and all classes.",
                       style={'color': '#888', 'fontSize': '11px'}),
                dcc.Graph(
                    figure=go.Figure(go.Bar(
                        x=shap_sorted_vals[::-1], y=shap_sorted_feats[::-1],
                        orientation='h', marker_color='#00FF88',
                        marker_line_color='#30363d', marker_line_width=0.5
                    )).update_layout(
                        paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
                        font_color='#e6edf3', font_size=10,
                        margin=dict(l=200, r=20, t=20, b=40),
                        xaxis=dict(gridcolor='#30363d', title='Mean |SHAP value|'),
                        yaxis=dict(gridcolor='#30363d'), height=450),
                    config={'displayModeBar': False})
            ], style=CSS['card']),
        ], width=6),
        dbc.Col([
            html.Div([
                html.H5("Test Set — True Label Distribution",
                        style={'color': '#00FF88', 'fontSize': '13px',
                               'letterSpacing': '1px'}),
                dcc.Graph(
                    figure=go.Figure(go.Bar(
                        x=[CLASS_NAMES[i] for i in np.unique(y_test)],
                        y=[np.sum(y_test == i) for i in np.unique(y_test)],
                        marker_color=[
                            BENIGN_COLOUR if CLASS_NAMES[i] == 'BENIGN'
                            else ATTACK_COLOUR for i in np.unique(y_test)]
                    )).update_layout(
                        paper_bgcolor='#0d1117', plot_bgcolor='#0d1117',
                        font_color='#e6edf3', font_size=10,
                        margin=dict(l=40, r=20, t=20, b=120),
                        xaxis=dict(gridcolor='#30363d', tickangle=45),
                        yaxis=dict(gridcolor='#30363d', title='Records'),
                        height=450),
                    config={'displayModeBar': False})
            ], style=CSS['card']),
        ], width=6),
    ]),
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H5("Model Comparison",
                        style={'color': '#00FF88', 'fontSize': '13px',
                               'letterSpacing': '1px', 'marginBottom': '10px'}),
                html.P("Held-out test set (20% of cleaned data).",
                       style={'color': '#888', 'fontSize': '11px'}),
                _build_model_table()
            ], style=CSS['card']),
        ], width=12),
    ]),
])
# ══════════════════════════════════════════════════════════════════
#  12.  MAIN LAYOUT
# ══════════════════════════════════════════════════════════════════
app.layout = html.Div([
    HEADER,
    dbc.Container([
        dbc.Tabs([
            dbc.Tab(label="Live Monitor", tab_id="tab-live",
                    label_style={'color': '#aaa'},
                    active_label_style={'color': '#00FF88'}),
            dbc.Tab(label="Model Insights", tab_id="tab-insights",
                    label_style={'color': '#aaa'},
                    active_label_style={'color': '#00FF88'}),
        ], id='tabs', active_tab='tab-live',
            style={'backgroundColor': '#0d1117',
                   'borderBottom': '1px solid #30363d',
                   'marginTop': '8px'}),
        html.Div(id='tab-content', style={'marginTop': '14px'})
    ], fluid=True, style={'padding': '0 14px'}),
], style={'backgroundColor': '#010409', 'minHeight': '100vh',
          'fontFamily': 'Consolas, monospace', 'color': '#e6edf3'})

# ══════════════════════════════════════════════════════════════════
#  13.  TAB ROUTING
# ══════════════════════════════════════════════════════════════════
@app.callback(Output('tab-content', 'children'), Input('tabs', 'active_tab'))
def render_tab(tab):
    if tab == 'tab-live':     return TAB_MONITOR
    if tab == 'tab-insights': return TAB_INSIGHTS
    return html.Div("Tab not found")

# ══════════════════════════════════════════════════════════════════
#  14.  CSV COLLAPSE TOGGLE
# ══════════════════════════════════════════════════════════════════
@app.callback(
    Output('csv-collapse', 'is_open'),
    Output('csv-chevron', 'children'),
    Input('csv-toggle-btn', 'n_clicks'),
    State('csv-collapse', 'is_open'),
    prevent_initial_call=True
)
def toggle_csv(n, is_open):
    new_open = not is_open
    return new_open, ('hide' if new_open else 'show')

# ══════════════════════════════════════════════════════════════════
#  15.  ATTACK FILTER CONTROL
# ══════════════════════════════════════════════════════════════════
@app.callback(
    Output('active-filter', 'data'),
    Output('filter-status', 'children'),
    Input('attack-filter-dropdown', 'value'),
    prevent_initial_call=True
)
def set_attack_filter(selected_attack):
    global filter_attack
    filter_attack = selected_attack
    if selected_attack is None:
        status = "Showing all traffic"
    else:
        status = f"Filtering: {selected_attack}"
    return selected_attack, status

# ══════════════════════════════════════════════════════════════════
#  16.  PIPELINE START / STOP
# ══════════════════════════════════════════════════════════════════
@app.callback(
    Output('pipeline-status', 'children'),
    Output('live-interval', 'disabled'),
    Input('btn-live-start', 'n_clicks'),
    Input('btn-live-stop', 'n_clicks'),
    State('iface-input', 'value'),
    State('capture-seconds', 'value'),
    prevent_initial_call=True
)
def control_pipeline(start, stop, iface, cap_secs):
    trigger = ctx.triggered_id
    global INTERFACE, CAPTURE_SECONDS
    if trigger == 'btn-live-start':
        if not pipeline_flag.is_set():
            selected_iface = iface or DEFAULT_IFACE
            CAPTURE_SECONDS = int(cap_secs or 10)
            print(f"[Control] Validating interface {selected_iface}...")
            success, pkt_bytes = _test_capture(selected_iface, duration=2)
            if not success or pkt_bytes < 100:
                error_msg = (f"Interface '{selected_iface}' failed validation. "
                             f"Run 'tshark -D' in PowerShell (Admin) to list available interfaces. "
                             f"Ensure the interface has active traffic.")
                print(f"[Control] ✗ {error_msg}")
                status = html.Span(
                    error_msg,
                    style={'color': '#FF4444', 'fontSize': '9px', 'lineHeight': '1.3'})
                return status, True
            INTERFACE = selected_iface
            while not result_queue.empty():
                try:
                    result_queue.get_nowait()
                except:
                    break
            pipeline_flag.set()
            t = threading.Thread(target=pipeline_worker, daemon=True)
            t.start()
            print(f"[Control] ✓ Started — iface={INTERFACE} cap={CAPTURE_SECONDS}s")
        status = html.Span(
            f"RUNNING  iface:{INTERFACE}  cycle:{CAPTURE_SECONDS}s",
            style={'color': '#00FF88', 'fontSize': '10px'})
        return status, False
    if trigger == 'btn-live-stop':
        pipeline_flag.clear()
        status = html.Span("STOPPED",
                           style={'color': '#FF4444', 'fontSize': '10px'})
        return status, True
    raise dash.exceptions.PreventUpdate

# ══════════════════════════════════════════════════════════════════
#  17.  RESULTS UPDATE
# ══════════════════════════════════════════════════════════════════
@app.callback(
    Output('live-rows', 'data'),
    Output('analysis-banner', 'children'),
    Output('sum-total', 'children'),
    Output('sum-attacks', 'children'),
    Output('sum-benign', 'children'),
    Output('attack-breakdown-container', 'children'),
    Output('results-table-container', 'children'),
    Output('table-row-count', 'children'),
    Output('latest-attack-info', 'children'),
    Input('live-interval', 'n_intervals'),
    Input('upload-csv', 'contents'),
    State('upload-csv', 'filename'),
    State('live-rows', 'data'),
    prevent_initial_call=True
)
def update_results(n_intervals, csv_contents, filename, existing_rows):
    trigger = ctx.triggered_id
    # ── LIVE QUEUE DRAIN ─────────────────────────────────────────
    if trigger == 'live-interval':
        new_rows = []
        errors = []
        warnings_list = []
        done = False
        for _ in range(500):
            try:
                item = result_queue.get_nowait()
            except queue.Empty:
                break
            t = item.get('type')
            if t == 'flow':
                new_rows.append(item)
            elif t == 'error':
                errors.append(item['msg'])
            elif t == 'warning':
                warnings_list.append(item['msg'])
            elif t == 'done':
                done = True
        if new_rows:
            _append_live_rows_to_log(new_rows)
        table_rows = _read_recent_live_rows(LIVE_TABLE_MAX_ROWS)
        if not new_rows and not errors and not warnings_list and not done:
            # Force-refresh table if persisted rows changed outside store state.
            if len(table_rows) != len(existing_rows or []):
                return _render_results(table_rows, live=pipeline_flag.is_set())
            raise dash.exceptions.PreventUpdate
        if not new_rows:
            existing = table_rows or (existing_rows or [])
            if errors:
                banner = html.Div(f"ERROR: {errors[-1]}", style=CSS['alert'])
                if existing:
                    res = list(_render_results(existing, live=not done))
                    res[1] = banner
                    return tuple(res)
                return (existing, banner, "—", "—", "—", html.Div(), html.Div(), "", html.Div())
            if warnings_list:
                banner = html.Div(f"WARNING: {warnings_list[-1]}", style=CSS['warn'])
                if existing:
                    res = list(_render_results(existing, live=not done))
                    res[1] = banner
                    return tuple(res)
                return (existing, banner, "—", "—", "—", html.Div(), html.Div(), "", html.Div())
            if done and existing:
                return _render_results(existing, live=False)
            raise dash.exceptions.PreventUpdate
        all_rows = table_rows or (existing_rows or [])
        print(f"[Dashboard] +{len(new_rows)} rows  total={len(all_rows)}")
        return _render_results(all_rows, live=pipeline_flag.is_set())
    # ── CSV BATCH UPLOAD ─────────────────────────────────────────
    if trigger == 'upload-csv' and csv_contents:
        try:
            df = _safe_read_csv(csv_contents, filename)
        except Exception as e:
            return ([], html.Div(f"Could not read file: {e}", style=CSS['alert']),
                    "—", "—", "—", html.Div(), html.Div(), "", html.Div())
        missing = [f for f in feat_names if f not in df.columns]
        if missing:
            return ([], html.Div(
                f"{len(missing)} required features missing. "
                "Ensure this is a CICIDS-format CSV.", style=CSS['alert']),
                    "—", "—", "—", html.Div(), html.Div(), "", html.Div())
        X = np.nan_to_num(df[feat_names].values.astype('float32'),
                          nan=0.0, posinf=0.0, neginf=0.0)
        preds = rf.predict(X)
        probs = rf.predict_proba(X)
        conf = probs[np.arange(len(preds)), preds]
        rows = []
        for i in range(len(preds)):
            pred_name = idx_to_name(preds[i])
            confidence = conf[i]
            if pred_name == 'BENIGN':
                status = 'BENIGN'
                severity = 'SAFE'
            elif confidence >= CONFIDENCE_THRESHOLD:
                status = 'CONFIRMED ATTACK'
                severity = get_attack_info(pred_name).get('severity', 'HIGH')
            else:
                status = 'SUSPICIOUS'
                severity = get_attack_info(pred_name).get('severity', 'MEDIUM')
            rows.append({
                'type': 'flow',
                'cycle': 'CSV',
                'flow': i + 1,
                'src_ip': '—',
                'dst_ip': '—',
                'prediction': pred_name,
                'confidence': f"{confidence * 100:.1f}%",
                'status': status,
                'severity': severity,
                'timestamp': filename,
            })
        return _render_results(rows, live=False)
    raise dash.exceptions.PreventUpdate

# ══════════════════════════════════════════════════════════════════
#  18.  RUN
# ══════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8050) 