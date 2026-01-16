
# Text-Based Cyber Threat Detection System

**Real-time detection of phishing, scams, harassment, malware, and fraud in text messages**

## 📋 Overview

This is a complete machine learning-powered solution that automatically analyzes text messages (SMS, Email, Social Media, WhatsApp) to identify and classify various cyber threats. The system combines rule-based keyword detection with machine learning algorithms to provide real-time threat assessment with risk scoring and confidence metrics.

## ✨ Features

### AI-Powered Detection
- **Multi-Threat Classification**: Identifies 6 threat categories
- **Hybrid Approach**: Combines keyword matching with RandomForest ML model
- **Real-time Analysis**: Processes messages in <100ms
- **Risk Scoring**: 0-100 risk level with visual indicators
- **Confidence Metrics**: Percentage-based detection confidence

### Technical Architecture
- **Backend**: FastAPI REST API with Python
- **Frontend**: Modern HTML/CSS/JS dashboard
- **ML Model**: RandomForest classifier with TF-IDF vectorization
- **Training Data**: Uses Kaggle SMS Spam Collection Dataset (5,572 samples)
- **Accuracy**: 99.8% on training data

## 🎯 Detection Categories

| Category       | Description                     | Example Detected                                   | Key Indicators                                             |
|----------------|---------------------------------|----------------------------------------------------|----------------------------------------------------------- |
| **Phishing**   | Credential stealing attempts    | "Verify your bank account now: http://bit.ly/fake" | verify, account, login, urgent, click, password, suspended |
| **Scam**       | Fraudulent offers and lotteries | "You won $100,000 lottery! Call now"               | free, win, prize, money, cash, winner, guaranteed          |
| **Harassment** | Abusive or threatening language | "I will hurt you tomorrow, you worthless piece"    | kill, hurt, die, hate, stupid, ugly, worthless, garbage    |
| **Malware**    | Malicious software distribution | "Download invoice.exe to view your document"       | .exe, .scr, .bat, download, install, virus, malware        |
| **Fraud**      | Personal/financial info theft   | "Your SSN 123-45-6789 needs verification"          | SSN, credit card, bank details, password, PIN, OTP         |
| **Safe**       | Legitimate messages             | "Hello, meeting at 3pm tomorrow in room 5"         | Normal communication patterns                              |

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Navigate to backend directory**
bash
cd backend


2. **Install dependencies**
bash
pip install fastapi uvicorn scikit-learn pandas numpy


3. **Run the backend server**
bash
python main.py


4. **Access the system**
   - **Dashboard**: http://localhost:8000
   - **API Documentation**: http://localhost:8000/docs
   - **Test API**: http://localhost:8000/analyze?text=your-message

## 📁 Project Structure


├── backend/
│   ├── main.py              # FastAPI application
│   ├── controller.py        # ML threat detection logic
│   ├── test_samples.py      # 20 test cases for validation
│   └── spam.csv            # Kaggle SMS dataset
├── frontend/
│   └── index.html          # Complete web dashboard


## 🛠️ Usage

### Using the Web Dashboard
1. Open http://localhost:8000 in your browser
2. Paste or type a message in the text area
3. Click "Analyze Threat" or press Ctrl+Enter
4. View detailed threat analysis with risk score and confidence

### Using the API
bash
# Analyze via GET request
curl "http://localhost:8000/analyze?text=Your%20bank%20account%20needs%20verification"

# Analyze via POST request
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text": "Free entry to win $1000 prize! Call now"}'


### Example Response
json
{
  "threat_category": "phishing",
  "risk_score": 85,
  "confidence": 92.5,
  "explanation": "⚠️ PHISHING DETECTED - Attempts to steal credentials through deceptive links or requests. Found indicators: 'verify', 'account', 'http://'.",
  "keywords_found": ["verify", "account", "http://"]
}


## 📊 Performance

| Metric | Value |
|--------|-------|
| Training Samples | 5,572 messages |
| Model Accuracy | 99.8% |
| Test Samples | 20 pre-configured |
| Threat Categories | 6 |
| Response Time | < 100ms |

## 🔬 Technical Implementation

### Detection Pipeline
1. **Text Preprocessing**: Input cleaning, lowercase conversion
2. **Keyword Analysis**: Multi-level matching against 200+ threat indicators
3. **ML Integration**: RandomForest prediction (spam vs ham)
4. **Category Decision**: Priority-based threat assignment
5. **Risk Calculation**: Dynamic scoring based on threat severity
6. **Result Generation**: Detailed explanation with found keywords

### Machine Learning Components
- **Algorithm**: RandomForest with 50 estimators
- **Vectorization**: TF-IDF with 500 features
- **Training Data**: 5,572 SMS messages from Kaggle dataset
- **Accuracy**: 99.8% on training data

### Dataset Reference
This project uses the **SMS Spam Collection Dataset** from Kaggle:
- **Dataset Link**: https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset
- **Total Messages**: 5,572
- **Spam Messages**: 747
- **Ham Messages**: 4,825
- **Format**: CSV with two columns (label, text)

## 🧪 Testing

The system includes comprehensive testing:

| Test Type | Samples | Description |
|-----------|---------|-------------|
| Basic Test | 20 | Runs all test samples |
| Advanced Test | 20 | Calculates accuracy percentage |
| Phishing Tests | 4 | Bank, PayPal, Netflix, Facebook |
| Scam Tests | 3 | Lottery, free iPhone, money making |
| Harassment Tests | 3 | Threats, insults, suicide |
| Malware Tests | 3 | .exe, .scr, .bat files |
| Fraud Tests | 3 | SSN, credit card, IRS |
| Safe Tests | 4 | Normal messages |

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Serve frontend dashboard |
| GET /POST | /analyze | Analyze text for threats |
| GET | /test | Run basic test samples |
| GET | /test-advanced | Run tests with accuracy metrics |
| GET | /stats | Get system statistics |
| GET | /health | Health check endpoint |

## 🙏 Acknowledgments

- **Kaggle**: For the SMS Spam Collection dataset
- **FastAPI**: For the web framework
- **Scikit-learn**: For machine learning tools
