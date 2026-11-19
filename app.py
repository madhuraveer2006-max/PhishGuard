
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from pathlib import Path
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
import json
import os

from database import get_db_connection, init_db
from feature_extractor import extract_features


# --------------------------------------------------
# FLASK CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "phishguard-development-secret-key"
)


# --------------------------------------------------
# LOAD MACHINE LEARNING MODELS
# --------------------------------------------------

def load_model(filename):
    model_path = MODEL_DIR / filename

    if not model_path.exists():
        print(f"WARNING: Model file not found: {filename}")
        return None

    try:
        return joblib.load(model_path)
    except Exception as error:
        print(f"Error loading {filename}: {error}")
        return None


random_forest_model = load_model("random_forest.pkl")
svm_model = load_model("svm.pkl")
gradient_boosting_model = load_model("gradient_boosting.pkl")


# --------------------------------------------------
# LOGIN REQUIRED DECORATOR
# --------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# HOME ROUTE
# --------------------------------------------------

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# --------------------------------------------------
# REGISTER ROUTE
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not password:
            flash("Please fill in all required fields.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "danger")
            return render_template("register.html")

        connection = get_db_connection()

        try:
            existing_user = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing_user:
                flash("Email already registered. Please login.", "warning")
                return render_template("register.html")

            hashed_password = generate_password_hash(password)

            connection.execute(
                """
                INSERT INTO users (full_name, email, password)
                VALUES (?, ?, ?)
                """,
                (full_name, email, hashed_password)
            )

            connection.commit()

            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))

        except Exception as error:
            connection.rollback()
            print("Registration error:", error)
            flash("Something went wrong during registration.", "danger")

        finally:
            connection.close()

    return render_template("register.html")


# --------------------------------------------------
# LOGIN ROUTE
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()

        try:
            user = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        finally:
            connection.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]
            session["user_email"] = user["email"]

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT ROUTE
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------
# DASHBOARD ROUTE
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    connection = get_db_connection()

    try:
        user_id = session["user_id"]

        total_scans = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM scan_history
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()["count"]

        phishing_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM scan_history
            WHERE user_id = ? AND status = 'Phishing'
            """,
            (user_id,)
        ).fetchone()["count"]

        legitimate_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM scan_history
            WHERE user_id = ? AND status = 'Legitimate'
            """,
            (user_id,)
        ).fetchone()["count"]

        recent_scans = connection.execute(
            """
            SELECT *
            FROM scan_history
            WHERE user_id = ?
            ORDER BY scanned_at DESC
            LIMIT 10
            """,
            (user_id,)
        ).fetchall()

    finally:
        connection.close()

    return render_template(
        "dashboard.html",
        user_name=session.get("user_name"),
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        recent_scans=recent_scans
    )



# --------------------------------------------------
# URL SCANNER ROUTE
# --------------------------------------------------

@app.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():

    result = None
    error = None
    scanned_url = ""
    risk = None
    model_results = {}

    if request.method == "POST":

        scanned_url = request.form.get("url", "").strip()

        if not scanned_url:
            error = "Please enter a URL to analyze."

        elif len(scanned_url) > 2048:
            error = "URL is too long. Please enter a shorter URL."

        elif not all([
            random_forest_model,
            svm_model,
            gradient_boosting_model
        ]):
            error = "ML models are not loaded. Please check the models folder."

        else:
            try:
                features = extract_features(scanned_url)
                feature_df = pd.DataFrame([features])

                # Individual model predictions
                rf_prediction = int(
                    random_forest_model.predict(feature_df)[0]
                )

                svm_prediction = int(
                    svm_model.predict(feature_df)[0]
                )

                gb_prediction = int(
                    gradient_boosting_model.predict(feature_df)[0]
                )

                predictions = [
                    rf_prediction,
                    svm_prediction,
                    gb_prediction
                ]

                # Individual model results
                model_results = {
                    "Random Forest": (
                        "Phishing" if rf_prediction == 1 else "Legitimate"
                    ),
                    "SVM": (
                        "Phishing" if svm_prediction == 1 else "Legitimate"
                    ),
                    "Gradient Boosting": (
                        "Phishing" if gb_prediction == 1 else "Legitimate"
                    )
                }

                # Majority voting
                phishing_votes = predictions.count(1)

                if phishing_votes >= 2:
                    result = "Phishing"
                else:
                    result = "Legitimate"

                # Risk level
                if phishing_votes == 3:
                    risk = "High"
                elif phishing_votes == 2:
                    risk = "Medium"
                else:
                    risk = "Low"

                # Save latest scan in session
                session["last_scan"] = {
                    "url": scanned_url,
                    "prediction": result,
                    "risk": risk,
                    "models": model_results
                }

                session.modified = True

                # DEBUG OUTPUT
                print("\n========== PHISHGUARD DEBUG ==========")
                print("URL:", scanned_url)
                print("Individual Predictions:", predictions)
                print("Model Results:", model_results)
                print("Final Result:", result)
                print("=======================================\n")

                # Save scan in database
                connection = get_db_connection()

                try:
                    connection.execute(
                        """
                        INSERT INTO scan_history
                        (user_id, url, status, risk)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            session["user_id"],
                            scanned_url,
                            result,
                            risk
                        )
                    )

                    connection.commit()

                finally:
                    connection.close()

            except Exception as exception:
                print("Scanner error:", exception)
                error = (
                    "Unable to analyze this URL. "
                    "Please check the feature extractor and model files."
                )

    return render_template(
        "index.html",
        result=result,
        prediction=result,
        risk=risk,
        scanned_url=scanned_url,
        model_results=model_results,
        error=error
    )

# --------------------------------------------------
# ABOUT PAGE
# --------------------------------------------------

@app.route("/about")
@login_required
def about():

    return render_template(
        "about.html",
        user_name=session.get("user_name")
    )


# --------------------------------------------------
# ML MODELS PAGE
# --------------------------------------------------

@app.route("/ml-models")
@login_required
def ml_models():

    metrics_path = MODEL_DIR / "model_metrics.json"
    metrics_data = {}

    if metrics_path.exists():

        try:
            with open(metrics_path, "r", encoding="utf-8") as file:
                metrics_data = json.load(file)

        except (json.JSONDecodeError, OSError) as error:
            print("Metrics file error:", error)
            flash("Unable to read model metrics.", "warning")

    else:
        flash(
            "Model metrics not found. Please run train.py first.",
            "warning"
        )

    return render_template(
        "ml_models.html",
        user_name=session.get("user_name"),
        models=metrics_data.get("models", {}),
        dataset=metrics_data.get("dataset", {}),
        last_scan=session.get("last_scan")
    )


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    init_db()

    print("\n===================================")
    print("       PHISHGUARD APPLICATION")
    print("===================================")
    print("Server: http://127.0.0.1:5000")
    print("===================================\n")

    app.run(debug=True)
