# Model Evaluation Metrics

**Date**: 2026-10-10T21:09:07.682348

**Dataset**: Full dataset

**Files**: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv, demo_training_data.csv

## Classification Metrics

| Metric | Value |
|--------|-------|
| Accuracy | 0.9998 |
| Precision (Attack) | 1.0000 |
| Recall (Attack) | 0.9996 |
| F1 Score (Attack) | 0.9998 |
| ROC-AUC | 1.0000 |

## Confusion Matrix

| | Predicted Normal | Predicted Attack |
|---|---|---|
| **Actual Normal** | TN = 18,381 | FP = 1 |
| **Actual Attack** | FN = 9 | TP = 25,594 |

## Class Distribution

| Set | Normal | Attack | Total |
|-----|--------|--------|-------|
| Train | 73,530 | 102,410 | 175,940 |
| Test | 18,382 | 25,603 | 43,985 |
| Total | 91,912 | 128,013 | 219,925 |

## Feature Importances

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | Fwd Packet Length Max | 0.1361 |
| 2 | Init_Win_bytes_forward | 0.1191 |
| 3 | Total Length of Fwd Packets | 0.1167 |
| 4 | Bwd Packet Length Mean | 0.1077 |
| 5 | Fwd Packet Length Mean | 0.0891 |
| 6 | Total Fwd Packets | 0.0815 |
| 7 | Bwd Packet Length Max | 0.0689 |
| 8 | Total Length of Bwd Packets | 0.0655 |
| 9 | Average Packet Size | 0.0509 |
| 10 | Fwd IAT Mean | 0.0506 |
| 11 | Total Backward Packets | 0.0274 |
| 12 | Flow IAT Std | 0.0230 |
| 13 | Bwd IAT Mean | 0.0210 |
| 14 | Flow Duration | 0.0103 |
| 15 | Flow Bytes/s | 0.0092 |
| 16 | Flow Packets/s | 0.0091 |
| 17 | Flow IAT Max | 0.0072 |
| 18 | ACK Flag Count | 0.0031 |
| 19 | Flow IAT Mean | 0.0029 |
| 20 | PSH Flag Count | 0.0007 |
| 21 | SYN Flag Count | 0.0000 |
| 22 | RST Flag Count | 0.0000 |

## Model Configuration

- **Algorithm**: Random Forest Classifier
- **n_estimators**: 100
- **max_depth**: 20
- **min_samples_split**: 5
- **min_samples_leaf**: 2
- **class_weight**: balanced
- **random_state**: 42
- **Preprocessing**: SimpleImputer(strategy=median)
- **Training time**: 5.6s
