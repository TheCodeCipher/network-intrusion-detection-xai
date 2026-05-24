# network-intrusion-detection-xai
# Network Intrusion Detection System with Explainability

A machine learning-based Network Intrusion Detection System (NIDS) built using the CICIDS2017 dataset with integrated Explainable AI (XAI) techniques using SHAP.

The system classifies network traffic into 15 categories including DDoS, brute-force, botnet, and benign traffic while providing interpretable threat analysis through feature attribution visualizations and a real-time monitoring dashboard.

---

## Features

- Multi-class intrusion detection
- Random Forest, XGBoost, and SVM model implementation
- SHAP explainability integration for interpretable predictions
- Real-time dashboard using Dash and Plotly
- Feature engineering and imbalance handling pipeline
- Live packet monitoring support
- Interactive visualization for attack analysis

---

## Tech Stack

### Languages & Libraries
- Python
- Scikit-learn
- XGBoost
- Pandas
- NumPy
- SHAP
- Dash
- Plotly

### Tools
- Wireshark / Tshark
- Jupyter Notebook
- Git & GitHub

---

## Dataset

This project uses the CICIDS2017 dataset developed by the Canadian Institute for Cybersecurity.

Due to GitHub file size limitations, the complete processed dataset and trained model artifacts are not included in this repository.

Dataset Source:  
https://www.unb.ca/cic/datasets/ids-2017.html

---

## Model Performance

| Model | Accuracy |
|------|------|
| Random Forest | ~99.8% |
| XGBoost | ~98.5% |
| SVM | ~96% |

---

## Explainability with SHAP

The project integrates SHAP (SHapley Additive exPlanations) to provide feature-level explanations for predictions. This improves transparency and helps security analysts understand why specific network flows are classified as attacks.

---

## Dashboard Preview

Add screenshots inside the `images/` folder and link them here.

Example:

```md
![Dashboard](images/dashboard.png)
```

---

## Project Structure

```bash
network-intrusion-detection-xai/
│
├── notebooks/
├── src/
├── dashboard/
├── images/
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Future Improvements

- Deep learning integration using LSTM
- Federated learning support
- Cloud deployment
- Automated retraining pipeline
- Enhanced real-time traffic analysis

---

## Contributors

- Tarun Das
- Sania Shanty
- Arkodyuti Bhattacharyya
- Adivi Ananya

---

## License

This project is licensed under the MIT License.
