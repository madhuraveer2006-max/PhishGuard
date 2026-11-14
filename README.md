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

3. Run the application:

   `python app.py`

4. Open in your browser:

   `http://127.0.0.1:5000`

## Important Note
PhishGuard is an academic project. Predictions are based on URL features and the training dataset. Results may vary on real-world URLs, and predictions should not be treated as a guarantee of website safety.