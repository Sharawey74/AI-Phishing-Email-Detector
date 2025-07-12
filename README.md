# AI Phishing Email Detector

![GitHub language count](https://img.shields.io/github/languages/top/Sharawey74/AI-Phishing-Email-Detector?color=brightgreen)
![License](https://img.shields.io/github/license/Sharawey74/AI-Phishing-Email-Detector)

A comprehensive machine learning-driven application designed for detecting phishing emails. This tool uses advanced natural language processing and machine learning models to analyze email content, headers, and metadata to identify potential phishing attempts with high accuracy.

![Phishing Detection Demo](docs/assets/demo_banner.png)

## 🚀 Features

- **Advanced Detection Engine**: Utilizes multiple ML models to achieve high accuracy and reduce false positives
- **Comprehensive Email Analysis**: Examines email headers, content, links, and attachments
- **Real-time Scanning & Risk Assesment**: Integrates with email clients for immediate threat detection
- **Detailed Threat Reports**: Provides comprehensive explanations of detected threats
- **User-friendly Dashboard**: Visualizes threat metrics and detection statistics
- **Continuous Learning**: Improves over time through feedback mechanisms
- **Multi-platform Support**: Works on various operating systems and email clients

## 📋 Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Technical Details](#technical-details)
- [Dataset](#dataset)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## 🔧 Installation

### Prerequisites

- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Sharawey74/AI-Phishing-Email-Detector.git
cd AI-Phishing-Email-Detector
```

2. Set up a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Download pre-trained models:
```bash
python scripts/download_models.py
```

## 🔍 Usage

### Command Line Interface

```bash
# Analyze a single email file
python detect.py --email path/to/email.eml

# Analyze multiple emails in a directory
python detect.py --directory path/to/email/folder

# Generate a detailed report
python detect.py --email path/to/email.eml --report
```

### API Usage

```python
from phishing_detector import PhishingDetector

# Initialize the detector
detector = PhishingDetector()

# Analyze an email file
result = detector.analyze_email("path/to/email.eml")

# Check results
if result.is_phishing:
    print(f"⚠️ Phishing detected (confidence: {result.confidence:.2f})")
    print(f"Detected indicators: {', '.join(result.indicators)}")
else:
    print("✅ Email appears legitimate")
```

### Web Interface

1. Start the web server:
```bash
python app.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Upload emails for analysis or configure email account integration

## 🧠 Technical Details

### Machine Learning Models

- **Text Classification**: BERT-based model fine-tuned on phishing email corpus
- **URL Analysis**: Ensemble model combining feature extraction and reputation data
- **Header Analysis**: Custom rule-based system with ML-enhanced pattern recognition
- **Image Analysis**: Convolutional Neural Network to detect logo spoofing

### Detection Techniques

- Natural Language Processing for content analysis
- URL and domain reputation checking
- Header anomaly detection
- Sender reputation validation
- Link and attachment scanning
- Behavioral pattern analysis

## 📊 Dataset

The system is trained on multiple datasets including:

- Public phishing email corpora
- Synthesized phishing attempts
- Legitimate email samples (with sensitive data removed)
- Custom-collected phishing samples

The training dataset contains over 100,000 labeled emails with balanced representation of phishing and legitimate communications across various attack types.

## 📁 Project Structure

```
AI-Phishing-Email-Detector/
├── data/                  # Training and testing datasets
├── models/                # Pre-trained ML models
├── src/                   # Source code
│   ├── analyzer/          # Email analysis components
│   ├── features/          # Feature extraction utilities
│   ├── models/            # Model definitions
│   └── utils/             # Helper functions
├── scripts/               # Utility scripts
├── tests/                 # Test suite
├── app.py                 # Web application
├── detect.py              # CLI tool
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the project's style guidelines and includes appropriate tests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📬 Contact

Project Link: [https://github.com/Sharawey74/AI-Phishing-Email-Detector](https://github.com/Sharawey74/AI-Phishing-Email-Detector)

---

*This tool is designed for security research and legitimate email security purposes only. Always respect privacy and applicable laws when analyzing email content.*
