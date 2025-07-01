# Phishing Email Detector

A sophisticated machine learning-based application for detecting phishing emails with detailed analysis and reporting capabilities.

## Features

- **Email Analysis**: Parse and analyze .eml files or raw email text
- **Multiple ML Models**: Support for Random Forest, Gradient Boosting, SVM, and Logistic Regression
- **Feature Extraction**: Comprehensive analysis of email headers, content, and URLs
- **Risk Assessment**: Detailed breakdown of phishing indicators with severity levels
- **URL Database**: Track and manage suspicious URLs found in emails
- **Report Generation**: Visualize analysis results with actionable recommendations
- **Modern UI**: Clean and intuitive graphical interface built with ttkbootstrap

## Installation

1. Clone the repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python run_detector.py
```

## Usage

### Running the Application

Launch the application by running `run_detector.py`. You'll see options to:
1. Run the detector application
2. Fix model issues (retrain the model)
3. Exit

### Analyzing Emails

The application provides two ways to analyze emails:
- **Upload .eml File**: Load an email file (.eml format)
- **Paste Text**: Enter raw email text directly

After loading an email, click "Analyze Email" to see detailed results.

### Testing with Sample Phishing Email

A sample phishing email is included in the `data` directory for testing:
- Path: `data/sample_phishing_test.eml`

### Training a New Model

To resolve the "Dataset must contain 'Body', 'Subject', or 'Content' column" error:
1. Run `python run_detector.py`
2. Choose option 2 to fix model issues
3. The application will train a new model using the included training data

## Project Structure

```
phishing_email_detector/
│
├── data/
│   ├── analysis_history.json       # History of analyzed emails
│   ├── suspicious_urls.json        # Database of suspicious URLs
│   ├── sample_phishing_test.eml    # Sample phishing email for testing
│   └── training_data.csv           # Training data for ML models
│
├── models/
│   ├── model_metadata.json         # Model performance metrics
│   ├── phishing_detector_model.joblib  # Trained ML model
│   └── tfidf_vectorizer.joblib     # Text vectorizer for features
│
├── main.py                         # Main application code
├── train_model.py                  # Script for training ML models
├── run_detector.py                 # Application launcher
└── README.md                       # This file
```

## Technical Details

### Email Feature Extraction

The system extracts and analyzes:
- Sender information (email, domain, name)
- Reply-To and Return-Path headers
- Subject line keywords and patterns
- Body content for suspicious patterns
- URLs and hyperlinks
- Attachment information
- Language and formatting red flags

### Machine Learning Approach

The detector uses TF-IDF vectorization on email content combined with extracted features to train classifier models that can identify phishing attempts with high accuracy.

## Troubleshooting

If you encounter the error "Dataset must contain 'Body', 'Subject', or 'Content' column":
1. Run `python run_detector.py`
2. Choose option 2 to fix model issues
3. This will train a new model with the correct data structure

If the application fails to start:
1. Check that all dependencies are installed
2. Ensure the Python environment is properly set up
3. Verify the file structure is intact

## License

This project is licensed under the MIT License - see the LICENSE file for details. 