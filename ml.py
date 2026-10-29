"""STEP 5 - Machine learning.
  python ml.py rf  data/cic_sample.csv [rows]   SUPERVISED Random Forest on a labelled CIC-IDS2017 CSV
  python ml.py iso data/features.csv            UNSUPERVISED Isolation Forest (trains on normal rows)
Report precision/recall honestly. Anomalies are leads, not proof."""
import sys
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from common import save_df, ROOT

def supervised(path, nrows=200_000):
    df = pd.read_csv(path, nrows=nrows, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
    y = (df["Label"].str.strip().str.upper() != "BENIGN").astype(int)       # 0 normal, 1 attack
    X = df.drop(columns=["Label"]).select_dtypes("number").astype("float32")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42).fit(Xtr, ytr)
    pred = model.predict(Xte)
    rep = classification_report(yte, pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(yte, pred, labels=[0, 1])
    print(classification_report(yte, pred, zero_division=0)); print(cm)
    save_df(pd.DataFrame([{"model": "Random Forest", "rows": len(df), "accuracy": rep["accuracy"],
            "precision": rep["1"]["precision"], "recall": rep["1"]["recall"], "f1": rep["1"]["f1-score"]}]),
            "ml_metrics")
    save_df(pd.DataFrame(cm, columns=["Pred normal", "Pred attack"]).assign(actual=["Normal", "Attack"]),
            "ml_confusion")
    imp = pd.Series(model.feature_importances_, index=X.columns).nlargest(15)
    save_df(imp.rename_axis("feature").reset_index(name="importance"), "ml_importance")
    joblib.dump(model, ROOT / "db" / "rf.joblib")

def unsupervised(path):
    df = pd.read_csv(path)
    truth = df.pop("is_attack") if "is_attack" in df else None           # only used to CHECK results
    train = df[truth == 0] if truth is not None else df
    iso = IsolationForest(contamination=0.02, random_state=42).fit(train)
    df["anomaly"] = iso.predict(df) == -1
    df["score"] = -iso.score_samples(df.drop(columns=["anomaly"]))
    save_df(df[df.anomaly].sort_values("score", ascending=False), "ml_anomalies")
    if truth is not None:
        caught = int((df.anomaly & (truth == 1)).sum()); fa = int((df.anomaly & (truth == 0)).sum())
        save_df(pd.DataFrame([{"attacks_total": int(truth.sum()), "attacks_caught": caught,
                "false_alarms": fa, "flagged": int(df.anomaly.sum())}]), "ml_iso")
        print(f"caught {caught}/{int(truth.sum())} attacks, {fa} false alarms")

if __name__ == "__main__":
    if sys.argv[1] == "rf": supervised(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 200_000)
    else: unsupervised(sys.argv[2])
