import os
import sys
import json
import joblib
import pandas as pd
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "ML",
    "dataset",
    "phishing_urls.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "ML",
    "models"
)

EVALUATION_DIR = os.path.join(
    BASE_DIR,
    "ML",
    "evaluation"
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

os.makedirs(
    EVALUATION_DIR,
    exist_ok=True
)


# ============================================================
# IMPORT EXISTING FEATURE EXTRACTOR
# ============================================================

sys.path.insert(
    0,
    BASE_DIR
)

from detector.feature_extractor import extract_features


# ============================================================
# DATASET COLUMN DETECTION
# ============================================================

def find_url_column(df):

    possible_names = [
        "url",
        "URL",
        "Url",
        "uri",
        "URI",
        "link",
        "Link",
        "website",
        "Website"
    ]

    for name in possible_names:

        if name in df.columns:
            return name

    # Fallback to first object/string column

    string_columns = []

    for column in df.columns:

        if df[column].dtype == "object":
            string_columns.append(column)

    if string_columns:

        return string_columns[0]

    return None


def find_label_column(
    df,
    url_column
):

    possible_names = [
        "label",
        "Label",
        "LABEL",
        "class",
        "Class",
        "ClassLabel",
        "target",
        "Target",
        "status",
        "Status",
        "type",
        "Type",
        "result",
        "Result"
    ]

    for name in possible_names:

        if (
            name in df.columns
            and name != url_column
        ):

            return name

    # Look for binary columns

    for column in df.columns:

        if column == url_column:
            continue

        unique_values = (
            df[column]
            .dropna()
            .unique()
        )

        if len(unique_values) == 2:

            return column

    return None


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_label(value):

    if pd.isna(value):
        return None

    value_string = str(
        value
    ).strip().lower()

    phishing_values = {
        "1",
        "phishing",
        "phish",
        "malicious",
        "malware",
        "bad",
        "fraud",
        "unsafe"
    }

    legitimate_values = {
        "0",
        "legitimate",
        "legit",
        "benign",
        "safe",
        "good",
        "normal"
    }

    if value_string in phishing_values:
        return 1

    if value_string in legitimate_values:
        return 0

    try:

        numeric_value = int(
            float(value_string)
        )

        if numeric_value in [0, 1]:
            return numeric_value

    except ValueError:

        pass

    return None


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print()
    print("=" * 65)
    print("PHISHING DETECTION ML TRAINING")
    print("=" * 65)

    print()
    print("[1/8] Loading dataset...")

    if not os.path.exists(
        DATASET_PATH
    ):

        print()
        print(
            "ERROR: Dataset not found:"
        )

        print(
            DATASET_PATH
        )

        sys.exit(1)

    df = pd.read_csv(
        DATASET_PATH
    )

    print()
    print(
        f"Dataset rows: {len(df):,}"
    )

    print(
        f"Dataset columns: {len(df.columns)}"
    )

    print()
    print("Columns:")

    for column in df.columns:

        print(
            f"  - {column}"
        )

    return df


# ============================================================
# PREPARE DATASET
# ============================================================

def prepare_dataset(df):

    print()
    print("[2/8] Preparing dataset...")

    url_column = find_url_column(
        df
    )

    label_column = find_label_column(
        df,
        url_column
    )

    if url_column is None:

        print(
            "ERROR: URL column could not be identified."
        )

        sys.exit(1)

    if label_column is None:

        print(
            "ERROR: Label column could not be identified."
        )

        sys.exit(1)

    print()
    print(
        f"URL column  : {url_column}"
    )

    print(
        f"Label column: {label_column}"
    )

    data = df[
        [
            url_column,
            label_column
        ]
    ].copy()

    # --------------------------------------------------------
    # Remove missing values
    # --------------------------------------------------------

    data = data.dropna()

    # --------------------------------------------------------
    # Normalize URL strings
    # --------------------------------------------------------

    data[url_column] = (
        data[url_column]
        .astype(str)
        .str.strip()
    )

    # --------------------------------------------------------
    # Remove empty URLs
    # --------------------------------------------------------

    data = data[
        data[url_column] != ""
    ]

    # --------------------------------------------------------
    # Remove duplicate URLs
    # --------------------------------------------------------

    before_duplicates = len(
        data
    )

    data = data.drop_duplicates(
        subset=[url_column]
    )

    removed_duplicates = (
        before_duplicates
        - len(data)
    )

    print()
    print(
        f"Removed duplicate URLs: "
        f"{removed_duplicates:,}"
    )

    # --------------------------------------------------------
    # Normalize labels
    # --------------------------------------------------------

    data["target"] = (
        data[label_column]
        .apply(normalize_label)
    )

    before_labels = len(
        data
    )

    data = data.dropna(
        subset=["target"]
    )

    removed_labels = (
        before_labels
        - len(data)
    )

    print(
        f"Removed unknown labels: "
        f"{removed_labels:,}"
    )

    data["target"] = (
        data["target"]
        .astype(int)
    )

    # --------------------------------------------------------
    # Class distribution
    # --------------------------------------------------------

    print()
    print("Class distribution:")

    counts = (
        data["target"]
        .value_counts()
        .sort_index()
    )

    for label, count in counts.items():

        if label == 0:
            name = "Legitimate"
        else:
            name = "Phishing"

        print(
            f"  {name}: {count:,}"
        )

    if data["target"].nunique() < 2:

        print()
        print(
            "ERROR: Both legitimate and phishing "
            "classes are required."
        )

        sys.exit(1)

    return data, url_column


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def build_features(
    data,
    url_column
):

    print()
    print("[3/8] Extracting URL features...")

    feature_rows = []

    total = len(data)

    for index, url in enumerate(
        data[url_column],
        start=1
    ):

        try:

            features = extract_features(
                url
            )

            feature_rows.append(
                features
            )

        except Exception as error:

            print()
            print(
                f"Feature extraction error "
                f"at row {index}: {error}"
            )

            feature_rows.append({})

        if index % 5000 == 0:

            print(
                f"  Processed "
                f"{index:,}/{total:,}"
            )

    X = pd.DataFrame(
        feature_rows
    )

    # --------------------------------------------------------
    # Clean feature matrix
    # --------------------------------------------------------

    X = X.fillna(0)

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.fillna(0)

    y = (
        data["target"]
        .reset_index(drop=True)
    )

    X = X.reset_index(
        drop=True
    )

    print()
    print(
        f"Feature matrix: "
        f"{X.shape[0]:,} samples × "
        f"{X.shape[1]} features"
    )

    print()
    print("Features used:")

    for feature in X.columns:

        print(
            f"  - {feature}"
        )

    return X, y


# ============================================================
# MODEL EVALUATION
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test,
    model_name
):

    print()
    print("=" * 65)
    print(
        f"{model_name} RESULTS"
    )
    print("=" * 65)

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    # --------------------------------------------------------
    # ROC-AUC
    # --------------------------------------------------------

    try:

        probabilities = (
            model.predict_proba(
                X_test
            )[:, 1]
        )

        roc_auc = roc_auc_score(
            y_test,
            probabilities
        )

    except Exception:

        roc_auc = 0

    # --------------------------------------------------------
    # Print metrics
    # --------------------------------------------------------

    print()
    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print()
    print(
        "Classification Report:"
    )

    print()

    report = classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )

    print(
        report
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(
        "Confusion Matrix:"
    )

    print(
        matrix
    )

    return {
        "accuracy": float(
            accuracy
        ),

        "precision": float(
            precision
        ),

        "recall": float(
            recall
        ),

        "f1": float(
            f1
        ),

        "roc_auc": float(
            roc_auc
        ),

        "predictions": predictions,

        "confusion_matrix": matrix
    }


# ============================================================
# CONFUSION MATRIX VISUALIZATION
# ============================================================

def create_confusion_matrix_plot(
    matrix,
    model_name
):

    print()
    print(
        "Creating confusion matrix..."
    )

    figure = plt.figure(
        figsize=(7, 6)
    )

    axis = figure.add_subplot(
        111
    )

    image = axis.imshow(
        matrix
    )

    figure.colorbar(
        image,
        ax=axis
    )

    axis.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=[
            "Legitimate",
            "Phishing"
        ],
        yticklabels=[
            "Legitimate",
            "Phishing"
        ],
        xlabel="Predicted Label",
        ylabel="Actual Label",
        title=f"{model_name} - Confusion Matrix"
    )

    # --------------------------------------------------------
    # Add values to cells
    # --------------------------------------------------------

    for row in range(
        matrix.shape[0]
    ):

        for column in range(
            matrix.shape[1]
        ):

            axis.text(
                column,
                row,
                f"{matrix[row, column]:,}",
                ha="center",
                va="center"
            )

    figure.tight_layout()

    output_path = os.path.join(
        EVALUATION_DIR,
        "confusion_matrix.png"
    )

    figure.savefig(
        output_path,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close(
        figure
    )

    print(
        f"Saved: {output_path}"
    )


# ============================================================
# RANDOM FOREST FEATURE IMPORTANCE
# ============================================================

def create_feature_importance_plot(
    model,
    feature_names
):

    print()
    print(
        "Analyzing Random Forest feature importance..."
    )

    # --------------------------------------------------------
    # Extract importance
    # --------------------------------------------------------

    importance_values = (
        model.feature_importances_
    )

    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance": importance_values
    })

    importance_df = (
        importance_df
        .sort_values(
            "importance",
            ascending=False
        )
        .reset_index(drop=True)
    )

    # --------------------------------------------------------
    # Print top features
    # --------------------------------------------------------

    print()
    print(
        "Top 15 Features:"
    )

    print()

    for index, row in (
        importance_df.head(15)
        .iterrows()
    ):

        print(
            f"{index + 1:2}. "
            f"{row['feature']:<35} "
            f"{row['importance']:.6f}"
        )

    # --------------------------------------------------------
    # Save full importance CSV
    # --------------------------------------------------------

    importance_csv = os.path.join(
        EVALUATION_DIR,
        "feature_importance.csv"
    )

    importance_df.to_csv(
        importance_csv,
        index=False
    )

    print()
    print(
        f"Saved: {importance_csv}"
    )

    # --------------------------------------------------------
    # Plot top 15
    # --------------------------------------------------------

    top_features = (
        importance_df
        .head(15)
        .sort_values(
            "importance",
            ascending=True
        )
    )

    figure = plt.figure(
        figsize=(10, 7)
    )

    axis = figure.add_subplot(
        111
    )

    axis.barh(
        top_features["feature"],
        top_features["importance"]
    )

    axis.set_xlabel(
        "Importance"
    )

    axis.set_ylabel(
        "Feature"
    )

    axis.set_title(
        "Random Forest - Top 15 Feature Importance"
    )

    figure.tight_layout()

    output_path = os.path.join(
        EVALUATION_DIR,
        "feature_importance.png"
    )

    figure.savefig(
        output_path,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close(
        figure
    )

    print(
        f"Saved: {output_path}"
    )

    return importance_df


# ============================================================
# SAVE METRICS
# ============================================================

def save_metrics(
    logistic_results,
    random_forest_results
):

    metrics = {
        "Logistic Regression": {
            "accuracy":
                logistic_results["accuracy"],

            "precision":
                logistic_results["precision"],

            "recall":
                logistic_results["recall"],

            "f1_score":
                logistic_results["f1"],

            "roc_auc":
                logistic_results["roc_auc"]
        },

        "Random Forest": {
            "accuracy":
                random_forest_results["accuracy"],

            "precision":
                random_forest_results["precision"],

            "recall":
                random_forest_results["recall"],

            "f1_score":
                random_forest_results["f1"],

            "roc_auc":
                random_forest_results["roc_auc"]
        }
    }

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    json_path = os.path.join(
        EVALUATION_DIR,
        "model_metrics.json"
    )

    with open(
        json_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4
        )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    csv_data = []

    for model_name, values in (
        metrics.items()
    ):

        row = {
            "model": model_name
        }

        row.update(
            values
        )

        csv_data.append(
            row
        )

    metrics_df = pd.DataFrame(
        csv_data
    )

    csv_path = os.path.join(
        EVALUATION_DIR,
        "model_metrics.csv"
    )

    metrics_df.to_csv(
        csv_path,
        index=False
    )

    print()
    print(
        f"Saved metrics: {json_path}"
    )

    print(
        f"Saved metrics: {csv_path}"
    )


# ============================================================
# SAVE BEST MODEL
# ============================================================

def save_best_model(
    logistic_model,
    logistic_results,
    random_forest_model,
    random_forest_results,
    feature_names
):

    print()
    print("[7/8] Selecting best model...")

    # --------------------------------------------------------
    # F1 score is primary selection metric
    # --------------------------------------------------------

    if (
        random_forest_results["f1"]
        >= logistic_results["f1"]
    ):

        best_model = (
            random_forest_model
        )

        best_name = (
            "Random Forest"
        )

        best_results = (
            random_forest_results
        )

    else:

        best_model = (
            logistic_model
        )

        best_name = (
            "Logistic Regression"
        )

        best_results = (
            logistic_results
        )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    model_path = os.path.join(
        MODEL_DIR,
        "phishing_model.joblib"
    )

    joblib.dump(
        best_model,
        model_path
    )

    # --------------------------------------------------------
    # Save feature names
    # --------------------------------------------------------

    feature_path = os.path.join(
        MODEL_DIR,
        "feature_names.joblib"
    )

    joblib.dump(
        list(feature_names),
        feature_path
    )

    print()
    print(
        f"Best model: {best_name}"
    )

    print(
        f"Best F1 Score: "
        f"{best_results['f1']:.4f}"
    )

    print()
    print(
        f"Model saved to:"
    )

    print(
        model_path
    )

    print()
    print(
        f"Feature names saved to:"
    )

    print(
        feature_path
    )

    return (
        best_name,
        best_results
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # 1. Load dataset
    # --------------------------------------------------------

    df = load_dataset()

    # --------------------------------------------------------
    # 2. Prepare dataset
    # --------------------------------------------------------

    data, url_column = prepare_dataset(
        df
    )

    # --------------------------------------------------------
    # 3. Build feature matrix
    # --------------------------------------------------------

    X, y = build_features(
        data,
        url_column
    )

    # --------------------------------------------------------
    # 4. Train/test split
    # --------------------------------------------------------

    print()
    print(
        "[4/8] Creating train/test split..."
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y
        )
    )

    print()
    print(
        f"Training samples: "
        f"{len(X_train):,}"
    )

    print(
        f"Testing samples : "
        f"{len(X_test):,}"
    )

    # --------------------------------------------------------
    # 5. Train models
    # --------------------------------------------------------

    print()
    print(
        "[5/8] Training models..."
    )

    # ========================================================
    # LOGISTIC REGRESSION
    # ========================================================

    print()
    print(
        "Training Logistic Regression..."
    )

    logistic_model = Pipeline(
        [
            (
                "scaler",
                StandardScaler()
            ),

            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42
                )
            )
        ]
    )

    logistic_model.fit(
        X_train,
        y_train
    )

    logistic_results = evaluate_model(
        logistic_model,
        X_test,
        y_test,
        "LOGISTIC REGRESSION"
    )

    # ========================================================
    # RANDOM FOREST
    # ========================================================

    print()
    print(
        "Training Random Forest..."
    )

    random_forest_model = (
        RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
    )

    random_forest_model.fit(
        X_train,
        y_train
    )

    random_forest_results = evaluate_model(
        random_forest_model,
        X_test,
        y_test,
        "RANDOM FOREST"
    )

    # --------------------------------------------------------
    # 6. Evaluation
    # --------------------------------------------------------

    print()
    print(
        "[6/8] Generating evaluation artifacts..."
    )

    create_confusion_matrix_plot(
        random_forest_results[
            "confusion_matrix"
        ],
        "Random Forest"
    )

    importance_df = (
        create_feature_importance_plot(
            random_forest_model,
            list(X.columns)
        )
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    save_metrics(
        logistic_results,
        random_forest_results
    )

    # --------------------------------------------------------
    # 7. Save best model
    # --------------------------------------------------------

    (
        best_name,
        best_results
    ) = save_best_model(
        logistic_model,
        logistic_results,
        random_forest_model,
        random_forest_results,
        X.columns
    )

    # --------------------------------------------------------
    # 8. Final summary
    # --------------------------------------------------------

    print()
    print(
        "[8/8] TRAINING AND EVALUATION COMPLETE"
    )

    print("=" * 65)

    print()
    print(
        "MODEL COMPARISON"
    )

    print()

    print(
        f"{'Metric':<15}"
        f"{'Logistic Regression':>22}"
        f"{'Random Forest':>20}"
    )

    print(
        "-" * 60
    )

    print(
        f"{'Accuracy':<15}"
        f"{logistic_results['accuracy']:>22.4f}"
        f"{random_forest_results['accuracy']:>20.4f}"
    )

    print(
        f"{'Precision':<15}"
        f"{logistic_results['precision']:>22.4f}"
        f"{random_forest_results['precision']:>20.4f}"
    )

    print(
        f"{'Recall':<15}"
        f"{logistic_results['recall']:>22.4f}"
        f"{random_forest_results['recall']:>20.4f}"
    )

    print(
        f"{'F1 Score':<15}"
        f"{logistic_results['f1']:>22.4f}"
        f"{random_forest_results['f1']:>20.4f}"
    )

    print(
        f"{'ROC-AUC':<15}"
        f"{logistic_results['roc_auc']:>22.4f}"
        f"{random_forest_results['roc_auc']:>20.4f}"
    )

    print()

    print(
        f"Selected model: {best_name}"
    )

    print(
        f"Selected F1: "
        f"{best_results['f1']:.4f}"
    )

    print()

    print(
        "Evaluation files:"
    )

    print(
        f"  - {EVALUATION_DIR}\\confusion_matrix.png"
    )

    print(
        f"  - {EVALUATION_DIR}\\feature_importance.png"
    )

    print(
        f"  - {EVALUATION_DIR}\\feature_importance.csv"
    )

    print(
        f"  - {EVALUATION_DIR}\\model_metrics.csv"
    )

    print(
        f"  - {EVALUATION_DIR}\\model_metrics.json"
    )

    print()

    print("=" * 65)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()