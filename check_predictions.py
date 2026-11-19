
import os
import joblib
import pandas as pd

from feature_extractor import extract_features, FEATURES


# Test URLs
test_urls = [
    "https://google.com",
    "https://youtube.com",
    "https://wikipedia.org",
    "http://secure-login-account-verify.example.com"
]

# Model files
models = {
    "Random Forest": "models/random_forest.pkl",
    "SVM": "models/svm.pkl",
    "Gradient Boosting": "models/gradient_boosting.pkl"
}

print("=" * 65)
print("             PHISHGUARD - MODEL PREDICTION CHECK")
print("=" * 65)

print("\nPROJECT DIRECTORY:", os.getcwd())

print(
    "FEATURE EXTRACTOR:",
    os.path.abspath("feature_extractor.py")
)

print("\nFEATURES USED:", FEATURES)


# Load and test each model
for model_name, model_path in models.items():

    print("\n" + "-" * 65)
    print("MODEL:", model_name)
    print("MODEL PATH:", os.path.abspath(model_path))

    if not os.path.exists(model_path):
        print("ERROR: Model file not found!")
        continue

    try:
        model = joblib.load(model_path)

        print("FILE EXISTS: True")
        print("MODEL FEATURES:", model.n_features_in_)
        print("MODEL CLASSES:", model.classes_)

        for url in test_urls:

            print("\nURL:", url)

            features = extract_features(url)

            X = pd.DataFrame(
                [features],
                columns=FEATURES
            )

            prediction = model.predict(X)[0]

            result = (
                "Phishing" if prediction == 1
                else "Legitimate"
            )

            print("Extracted Features:", features)
            print("Prediction:", prediction)
            print("Result:", result)

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(X)[0]

                print("Probabilities:")

                for class_label, probability in zip(
                    model.classes_,
                    probabilities
                ):
                    label = (
                        "Phishing" if class_label == 1
                        else "Legitimate"
                    )

                    print(
                        f"  {label}: {probability * 100:.2f}%"
                    )

    except Exception as e:
        print("ERROR:", str(e))


print("\n" + "=" * 65)
print("                 CHECK COMPLETED")
print("=" * 65)
