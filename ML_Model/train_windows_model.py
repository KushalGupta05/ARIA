"""Train and evaluate the 15-counter Windows classifier used by the Wazuh feed."""
import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score

from frontend_db_setup import STATE_DIR
from telemetry_schema import CLASS_NAMES, FEATURE_KEYS


def train(csv_path: Path, output: Path):
    frame = pd.read_csv(csv_path, low_memory=False)
    frame.columns = [name.replace("(Intel R _82574L_GNC)", "_ActiveNIC_") for name in frame.columns]
    missing = sorted(set([*FEATURE_KEYS, "type"]) - set(frame.columns))
    if missing:
        raise ValueError(f"The Windows 10 CSV is missing these columns: {missing}")

    labels = frame["type"].astype(str).str.strip().str.lower()
    if set(labels) != set(CLASS_NAMES):
        raise ValueError(f"Expected all eight TON_IoT Windows labels. Found {sorted(set(labels))}")
    features = frame[FEATURE_KEYS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    target = labels.map({name: index for index, name in enumerate(CLASS_NAMES)})
    train_indices, test_indices = [], []
    for name in CLASS_NAMES:
        indices = frame.index[labels == name]
        boundary = int(len(indices) * 0.8)
        if boundary == 0 or boundary == len(indices):
            raise ValueError(f"Too few records for a train/test split of {name}")
        train_indices.extend(indices[:boundary])
        test_indices.extend(indices[boundary:])

    model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1)
    model.fit(features.loc[train_indices].to_numpy(), target.loc[train_indices])
    expected = target.loc[test_indices]
    predicted = model.predict(features.loc[test_indices].to_numpy())
    print(f"Train rows: {len(train_indices)} | Test rows: {len(test_indices)} | Counters: {len(FEATURE_KEYS)}")
    print(classification_report(expected, predicted, labels=range(len(CLASS_NAMES)), target_names=CLASS_NAMES, digits=4, zero_division=0))
    print(f"Accuracy: {accuracy_score(expected, predicted):.4f} | Macro F1: {f1_score(expected, predicted, average='macro'):.4f}")
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    print(f"Saved model to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="UNSW Train_Test_Windows_10.csv")
    parser.add_argument("--output", type=Path, default=STATE_DIR / "aria_rf_model.pkl")
    args = parser.parse_args()
    train(args.csv, args.output)
