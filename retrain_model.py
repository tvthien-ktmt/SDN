#!/usr/bin/env python3
# retrain_model.py
# Retrain Random Forest tren du lieu da thu thap duoc
# Co the chay tren may tinh Windows hoac Google Colab
#
# Cach dung:
#   python retrain_model.py
#   hoac tren Colab: upload collected_data.csv roi chay

import pandas as pd
import joblib
import numpy as np
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# ================================================================
# 1. NAP VA KIEM TRA DATA
# ================================================================
print("="*60)
print("BUOC 1: Nap du lieu")
print("="*60)

INPUT_CSV  = 'collected_data.csv'   # File tu thu thap
OUTPUT_SAV = 'ddos_model.sav'       # File model xuat ra

df = pd.read_csv(INPUT_CSV)
print(f"Tong so mau: {len(df)}")
print(f"Cot: {df.columns.tolist()}")
print()
print("Phan phoi nhan:")
print(df['label'].value_counts())
print()

# Kiem tra du lieu
assert df.isnull().sum().sum() == 0, "CANH BAO: Co gia tri NULL trong du lieu!"
assert 0 in df['label'].values, "CANH BAO: Khong co mau SAFE (label=0)!"
assert 1 in df['label'].values, "CANH BAO: Khong co mau ATTACK (label=1)!"

n_safe   = (df['label'] == 0).sum()
n_attack = (df['label'] == 1).sum()
ratio = min(n_safe, n_attack) / max(n_safe, n_attack)
print(f"Balance ratio: {ratio:.3f} (tot nhat >= 0.8)")
if ratio < 0.7:
    print("CANH BAO: Du lieu mat can bang! Can thu thap them mau cho nhan thieu.")

# ================================================================
# 2. CHUAN BI FEATURES
# ================================================================
print("\n" + "="*60)
print("BUOC 2: Chuan bi features")
print("="*60)

# Chi dung cac features co y nghia (bo entropy vi luon = 0)
FEATURES = [
    'pkt_rate',          # Packets/giay - feature quan trong nhat
    'byte_rate',         # Bytes/giay
    'flow_dur',          # Thoi gian flow
    'avg_pkt_size',      # Kich thuoc trung binh goi tin
    'protocol',          # Giao thuc: 1=ICMP, 6=TCP, 17=UDP
    'n_flows_same_src',  # So luong flow cung nguon
]
X = df[FEATURES]
y = df['label']

print(f"Features su dung: {FEATURES}")
print()
print("Thong ke features:")
print(X.describe().to_string())

# ================================================================
# 3. TRAIN MODEL
# ================================================================
print("\n" + "="*60)
print("BUOC 3: Train Random Forest")
print("="*60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train: {len(X_train)} mau | Test: {len(X_test)} mau")

# Random Forest voi cac hyperparameter hop ly hon
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,          # Gioi han do sau tranh overfitting
    min_samples_split=5,   # Can it nhat 5 mau moi chia node
    min_samples_leaf=2,    # Can it nhat 2 mau o leaf node
    class_weight='balanced', # Tu dong can bang neu mat can bang
    random_state=42,
    n_jobs=-1              # Dung tat ca CPU cores
)

print("Dang train model...")
model.fit(X_train, y_train)
print("Train xong!")

# ================================================================
# 4. DANH GIA
# ================================================================
print("\n" + "="*60)
print("BUOC 4: Danh gia hieu suat")
print("="*60)

# Cross-validation
cv_acc = cross_val_score(model, X, y, cv=5, scoring='accuracy')
cv_f1  = cross_val_score(model, X, y, cv=5, scoring='f1')
print(f"Cross-Val Accuracy: {cv_acc.mean():.4f} +/- {cv_acc.std():.4f}")
print(f"Cross-Val F1:       {cv_f1.mean():.4f} +/- {cv_f1.std():.4f}")
print()

# Test set
y_pred = model.predict(X_test)
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=['SAFE', 'ATTACK']))

cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(f"              Predict SAFE  Predict ATTACK")
print(f"Actual SAFE:       {cm[0][0]:5d}          {cm[0][1]:5d}")
print(f"Actual ATTACK:     {cm[1][0]:5d}          {cm[1][1]:5d}")

# Feature importance
print()
print("Feature Importance:")
for name, imp in sorted(zip(FEATURES, model.feature_importances_), key=lambda x: -x[1]):
    bar = '#' * int(imp * 40)
    print(f"  {name:12s}: {imp:.4f}  {bar}")

# ================================================================
# 5. LUU MODEL
# ================================================================
print("\n" + "="*60)
print("BUOC 5: Luu model")
print("="*60)

# Luu model kem metadata de biet dung features nao
model_data = {
    'model': model,
    'features': FEATURES,
    'accuracy': cv_acc.mean(),
    'f1': cv_f1.mean()
}
joblib.dump(model, OUTPUT_SAV)
print(f"Da luu model vao: {OUTPUT_SAV}")
print()
print("QUAN TRONG: Model moi dung 6 features: pkt_rate, byte_rate, flow_dur, avg_pkt_size, protocol, n_flows_same_src")
print("=> Chay lai data_collector.py (da cap nhat) de thu thap dung format!")
print()

# In ra doan code de copy vao detection_system.py
print("="*60)
print("COPY DOAN CODE NAY VAO detection_system.py:")
print("="*60)
print("""
    features = pd.DataFrame(
        [[pkt_rate, byte_rate, duration]],
        columns=['pkt_rate', 'byte_rate', 'flow_dur']
    )
""")
