import pandas as pd
import numpy as np
import joblib
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

cols = ["Label", "Flow ID", "Source IP", "Destination IP", "Timestamp"]

def data_process(path: str):
    df = pd.read_csv(path, skipinitialspace=True)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].astype(str).str.strip().str.upper()

    # Map anything containing "BENIGN" or "NORMAL" to safe
    y = df["Label"].apply(lambda x: 0 if ("BENIGN" in x or "NORMAL" in x) else 1)
    X = df.drop(columns=[c for c in cols if c in df.columns])
    X = X.replace(["Infinity", "inf", "-Infinity", "-inf", "INFINITY"], np.nan)

    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    mask = X.notna().all(axis=1)
    X = X.loc[mask].astype(np.float64)
    y = y.loc[mask]

    print("Unique labels:", df["Label"].unique())
    print("Attack ratio:", y.mean())

    return X, y

#----------------------------------------------------------------------------
#----------------------------------------------------------------------------

train_files = [
    "data//Monday-WorkingHours.pcap_ISCX.csv",
    "data//Tuesday-WorkingHours.pcap_ISCX.csv",
    "data//Wednesday-workingHours.pcap_ISCX.csv",
    "data//Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "data//Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "data//Friday-WorkingHours-Morning.pcap_ISCX.csv",
]

test_file = "data//Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

X_list, y_list = [],[]

for f in train_files:
    X_f, y_f = data_process(f)
    X_list.append(X_f)
    y_list.append(y_f)
    print(f"{f}: X={X_f.shape}, y attack ratio={y_f.mean():.4f}")

X_train_all = pd.concat(X_list, axis=0)
y_train_all = pd.concat(y_list, axis=0)

X_train_all = X_train_all.reset_index(drop=True)
y_train_all = y_train_all.reset_index(drop=True)

print("\nCombined training set:")
print("X:", X_train_all.shape, "y:", y_train_all.shape)
print("Class counts:\n", y_train_all.value_counts())
print("Attack ratio:", y_train_all.mean())

#----------------------------------------------------------------------------
#----------------------------------------------------------------------------

train_features = X_train_all.columns.tolist()
X_test, y_test = data_process(test_file)

X_test = X_test.reindex(columns=train_features, fill_value=0)
X_test = X_test[train_features]

print("\nHoldout test set:", X_test.shape)
print("Holdout class counts:\n", y_test.value_counts())

#----------------------------------------------------------------------------
#----------------------------------------------------------------------------

def undersample_benign(X, y, benign_to_attack_ratio=3, random_state=42):
    # Split benign and attack rows
    idx_attack = y[y == 1].index
    idx_benign = y[y == 0].index

    n_attack = len(idx_attack)
    n_benign_target = benign_to_attack_ratio * n_attack

    # If benign is already small, do nothing
    if len(idx_benign) <= n_benign_target:
        return X, y

    # Sample benign down
    idx_benign_sample = np.random.RandomState(random_state).choice(
        idx_benign, size=n_benign_target, replace=False
    )

    idx_keep = np.concatenate([idx_attack, idx_benign_sample])
    X_bal = X.loc[idx_keep]
    y_bal = y.loc[idx_keep]

    return X_bal, y_bal

X_bal, y_bal = undersample_benign(X_train_all, y_train_all, benign_to_attack_ratio=3)

print("After undersampling:")
print("X:", X_bal.shape, "y:", y_bal.shape)
print("Class counts:\n", y_bal.value_counts())
print("Attack ratio:", y_bal.mean())

#----------------------------------------------------------------------------
#----------------------------------------------------------------------------

rf_model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced',
    max_depth=16,
    min_samples_leaf=5,
    min_samples_split=10,
    max_features="sqrt"
)

rf_model.fit(X_bal, y_bal)
print("Model Trained")

#----------------------------------------------------------------------------
#----------------------------------------------------------------------------

y_pred = rf_model.predict(X_test)

print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification report:\n", classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

#----------------------------------------------------------------------------
#----------------------------------------------------------------------------

joblib.dump(rf_model, 'E:\\Project Portfolio\\Dissertation\\Final-Year-IDS\\models\\IDS_ver_2.joblib')