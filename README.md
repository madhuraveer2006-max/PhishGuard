# PhishGuard – Phishing URL Detection System

PhishGuard is a machine learning-based web application that analyzes URL features and classifies URLs as legitimate or potentially phishing.

## Features
- User Registration and Login
- URL Feature Extraction
- Phishing URL Classification
- Three Machine Learning Models
- Majority Voting Prediction
- Scan History Dashboard
- Model Performance Comparison
- Confusion Matrix Visualization

## Machine Learning Algorithms
1. Random Forest
2. Support Vector Machine (SVM)
3. Gradient Boosting

## Technologies Used
- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- HTML, CSS, JavaScript
- Bootstrap
- Chart.js
- SQLite

## Dataset
Kaggle: Phishing URLs Dataset with Extracted Features

https://www.kaggle.com/datasets/victusadi/phishing-urls-dataset-with-extracted-features

## How to Run

1. Clone this repository.
2. Install the required packages:

   `pip install -r requirements.txt`

3. Train the models after installing the requirements (this creates/updates the
   model files and evaluation metrics):

   `python train.py`

4. Run the application:

   `python app.py`

5. Open in your browser:

   `http://127.0.0.1:5000`

## Model Evaluation Notes
- The dataset is class-imbalanced, so balanced accuracy and the confusion matrix should be reviewed alongside accuracy.
- The training script uses a stratified 80/20 train-test split with a fixed random state for repeatable evaluation.
- The HTTPS feature is extracted from the original URL scheme. Retrain the models with `python train.py` after this feature-extractor update.

## Important Note
PhishGuard is an academic project. Predictions are based on URL features and the training dataset. Results may vary on real-world URLs, and predictions should not be treated as a guarantee of website safety.