
PhishGuard AI
An AI-powered phishing detection and prevention tool that helps protect users from malicious emails and websites.
Features

Email Analysis: Detect phishing attempts in email content
URL Scanning: Analyze suspicious links and websites
Real-time Protection: Instant threat detection and alerts
Machine Learning: Advanced AI algorithms for accurate detection
User-friendly Interface: Simple and intuitive design

Installation

Clone the repository:

bashgit clone https://github.com/yourusername/PhishGuard-AI.git
cd PhishGuard-AI

Install dependencies:

bashpip install -r requirements.txt

Run the application:

bashpython src/main.py
Usage
Basic Usage
pythonfrom phishguard import PhishGuard

# Initialize the detector
detector = PhishGuard()

# Analyze an email
result = detector.analyze_email(email_content)
print(f"Phishing probability: {result.probability}")

# Check a URL
url_result = detector.check_url("https://suspicious-site.com")
print(f"URL safety: {url_result.status}")
Command Line Interface
bash# Scan an email file
python -m phishguard --email path/to/email.txt

# Check a URL
python -m phishguard --url https://example.com
