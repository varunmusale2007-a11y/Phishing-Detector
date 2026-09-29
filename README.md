# 🛡️ Phishing URL Detector

A **Machine Learning-based Phishing URL Detection Web Application** that analyzes URLs and determines whether they are **Safe** or **Potentially Phishing**.

The system extracts important features from a URL and uses a trained machine learning model to identify suspicious patterns commonly associated with phishing websites.

## 🚀 Features

* 🔍 **URL Analysis** – Enter any URL and analyze it instantly.
* 🤖 **Machine Learning Detection** – Uses ML-based URL feature analysis.
* 🟢 **Safe Detection** – Identifies URLs that appear legitimate.
* 🔴 **Phishing Detection** – Detects potentially malicious/phishing URLs.
* 📊 **Risk Assessment** – Provides a risk level based on URL characteristics.
* 🧠 **Feature Analysis** – Examines suspicious URL properties such as:

  * URL length
  * Number of dots
  * Number of special characters
  * HTTPS usage
  * Presence of IP address
  * Suspicious keywords
  * Number of subdomains
  * Use of URL shortening
  * Domain-related characteristics
* 📱 **Responsive Design** – Works on both desktop and mobile devices.
* ⚡ **Fast Results** – Provides URL classification without requiring the user to visit the website.
* 🌐 **Web-Based Interface** – Easy-to-use interface for security testing.

## 🎯 Objective

The main objective of this project is to provide an additional layer of protection against phishing attacks by analyzing URLs before users open them.

Phishing attacks often attempt to trick users into visiting fake websites that imitate legitimate services and collect sensitive information such as:

* Usernames
* Passwords
* Banking information
* Credit/debit card details
* OTPs
* Personal information

This project attempts to identify suspicious URLs using machine learning and URL-based features.

## 🏗️ System Architecture

```text
User
  │
  ▼
Enter URL
  │
  ▼
Web Interface
  │
  ▼
URL Feature Extraction
  │
  ├── URL Length
  ├── HTTPS
  ├── IP Address
  ├── Special Characters
  ├── Subdomains
  ├── Suspicious Keywords
  └── Other URL Features
  │
  ▼
Machine Learning Model
  │
  ▼
Prediction
  │
  ├── 🟢 SAFE
  │
  └── 🔴 PHISHING
  │
  ▼
Risk Result & Explanation
```

## 🛠️ Technologies Used

### Frontend

* HTML5
* CSS3
* JavaScript
* Responsive Web Design

### Backend

* Python
* Flask

### Machine Learning

* Scikit-learn
* Pandas
* NumPy

### Development & Deployment

* Git
* GitHub
* Python Virtual Environment

## 📂 Project Structure

```text
phishing-url-detector/
│
├── app.py
├── requirements.txt
├── README.md
│
├── model/
│   ├── phishing_model.pkl
│   └── scaler.pkl
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── script.js
│   └── images/
│
├── dataset/
│   └── phishing_dataset.csv
│
└── utils/
    └── feature_extraction.py
```

> The exact structure may vary depending on the implementation.

## ⚙️ How It Works

### 1. URL Input

The user enters a URL into the web application.

### 2. Feature Extraction

The application extracts measurable characteristics from the URL.

For example:

```text
URL Length
HTTPS Status
Number of Dots
Number of Subdomains
Special Characters
IP Address Usage
Suspicious Keywords
```

### 3. Machine Learning Prediction

The extracted features are passed to the trained machine learning model.

The model predicts whether the URL is:

```text
SAFE
```

or

```text
POTENTIALLY PHISHING
```

### 4. Result

The application displays the prediction along with relevant information about why the URL may be considered suspicious.

## 🧠 Machine Learning

The project can be trained using a dataset containing legitimate and phishing URLs.

Example:

```text
URL                                      Label
------------------------------------------------
https://www.google.com                    Safe
https://www.github.com                    Safe
suspicious-login-example.com              Phishing
fake-bank-login-example.com               Phishing
```

Possible algorithms include:

* Random Forest
* Decision Tree
* Logistic Regression
* Support Vector Machine
* Gradient Boosting

The trained model can then be saved and loaded by the Flask backend.

## 📊 Model Evaluation

The model should be evaluated using metrics such as:

* Accuracy
* Precision
* Recall
* F1-Score
* Confusion Matrix

Example:

```text
Accuracy  : XX%
Precision : XX%
Recall    : XX%
F1 Score  : XX%
```

> Replace the values with the actual results from your trained model.

## 💻 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/phishing-url-detector.git
```

### 2. Open the project

```bash
cd phishing-url-detector
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment

**Windows:**

```bash
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
python app.py
```

The application will normally be available at:

```text
http://127.0.0.1:5000
```

## 🔐 Security Notice

This application is intended for **educational, research, and defensive cybersecurity purposes**.

The detector does not guarantee that a URL is completely safe or malicious. A URL classified as "Safe" should not automatically be considered trustworthy.

**Do not open suspicious URLs directly in your normal browser.**

For security testing, use isolated environments and trusted threat-intelligence datasets.

## 🧪 Testing

You can test the detector using:

### Legitimate URLs

```text
https://www.google.com
https://www.microsoft.com
https://www.github.com
https://www.apple.com
https://www.wikipedia.org
```

### Phishing/Malicious URL Sources

For research datasets, use reputable threat-intelligence sources such as:

* PhishTank
* URLhaus
* Kaggle phishing URL datasets

Do not intentionally visit malicious URLs simply to test the detector. Submit them to your application as URL strings whenever possible.

## 🌐 Deployment

The frontend can be deployed using services such as:

* GitHub Pages — for static frontend applications
* Vercel — for supported frontend/serverless applications
* Render — suitable for Python/Flask applications
* Railway — suitable for backend applications

If the application requires a **Python Flask backend and ML model**, the backend must be deployed on a service that supports Python execution. GitHub Pages alone cannot run a Flask backend.

## 🔮 Future Improvements

Future versions can include:

* 🔗 Real-time threat-intelligence API integration
* 🧠 Deep learning-based URL classification
* 🌍 Domain reputation checking
* 🔒 SSL certificate analysis
* 📅 Domain age analysis
* 📈 Detailed risk scoring
* 🛡️ Browser extension integration
* 🚨 Real-time URL scanning
* 📧 Email phishing detection
* 🔍 QR-code URL scanning
* 🧩 Firewall/proxy integration
* 📊 Security analytics dashboard

## ⚠️ Disclaimer

This project is an **educational cybersecurity application** and should not be considered a replacement for professional security software, browser protection, antivirus software, or enterprise security systems.

Machine learning predictions can contain false positives and false negatives.

Always verify suspicious links through trusted sources before interacting with them.

## 👨‍💻 Author

**Varun Musale**

Engineering Student | Artificial Intelligence & Machine Learning

## ⭐ Contributing

Contributions, suggestions, and improvements are welcome.

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Commit your changes
5. Push the branch
6. Create a Pull Request

Live working on the website : 

## 📜 License

This project is intended for educational and research purposes.
