import os
import joblib
import pandas as pd

from detector.feature_extractor import extract_features


# ============================================================
# MODEL PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ML",
    "models",
    "phishing_model.joblib"
)

FEATURE_NAMES_PATH = os.path.join(
    BASE_DIR,
    "ML",
    "models",
    "feature_names.joblib"
)


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    if not os.path.exists(MODEL_PATH):
        return None

    try:

        return joblib.load(
            MODEL_PATH
        )

    except Exception:

        return None


# ============================================================
# LOAD FEATURE NAMES
# ============================================================

def load_feature_names():

    if not os.path.exists(
        FEATURE_NAMES_PATH
    ):
        return None

    try:

        return joblib.load(
            FEATURE_NAMES_PATH
        )

    except Exception:

        return None


# ============================================================
# ML ANALYSIS
# ============================================================

def analyze_ml(url):
    """
    Analyze a URL using the trained machine-learning model.

    Returns:
        prediction
        phishing_probability
        legitimate_probability
        model_available
        error
    """

    result = {
        "model_available": False,
        "prediction": None,
        "phishing_probability": None,
        "legitimate_probability": None,
        "error": None
    }

    # ========================================================
    # CHECK MODEL
    # ========================================================

    model = load_model()

    if model is None:

        result["error"] = (
            "Trained ML model was not found."
        )

        return result

    # ========================================================
    # LOAD FEATURE NAMES
    # ========================================================

    feature_names = load_feature_names()

    if feature_names is None:

        result["error"] = (
            "ML feature definition was not found."
        )

        return result

    result["model_available"] = True

    # ========================================================
    # EXTRACT FEATURES
    # ========================================================

    try:

        features = extract_features(
            url
        )

        feature_vector = pd.DataFrame(
            [features]
        )

        # Make sure the live feature order
        # exactly matches training order.

        feature_vector = (
            feature_vector
            .reindex(
                columns=feature_names,
                fill_value=0
            )
        )

        feature_vector = (
            feature_vector
            .apply(
                pd.to_numeric,
                errors="coerce"
            )
            .fillna(0)
        )

    except Exception as error:

        result["error"] = (
            f"Feature extraction failed: {error}"
        )

        return result

    # ========================================================
    # PREDICTION
    # ========================================================

    try:

        prediction = model.predict(
            feature_vector
        )[0]

        probabilities = model.predict_proba(
            feature_vector
        )[0]

        # The model was trained as:
        # 0 = legitimate
        # 1 = phishing

        legitimate_probability = (
            probabilities[0]
            * 100
        )

        phishing_probability = (
            probabilities[1]
            * 100
        )

        result["prediction"] = int(
            prediction
        )

        result["legitimate_probability"] = round(
            legitimate_probability,
            2
        )

        result["phishing_probability"] = round(
            phishing_probability,
            2
        )

    except Exception as error:

        result["error"] = (
            f"ML prediction failed: {error}"
        )

    return result