from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from phishing_detector import PhishingDetector
import sqlite3
from datetime import datetime
import os
import traceback

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this to a random secret key

# Initialize detector
detector = PhishingDetector()

# Check if model exists and load it
if os.path.exists('phishing_model.pkl'):
    try:
        detector.load_model('phishing_model.pkl')
        print("Model loaded successfully!")
    except Exception as e:
        print(f"Error loading model: {e}")
        detector = None
else:
    print("No trained model found. You'll need to train a model first.")
    detector = None

def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('phishing_logs.db')
    cursor = conn.cursor()
    
    # Create analysis_logs table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            email_content TEXT,
            subject TEXT,
            sender TEXT,
            is_phishing INTEGER,
            confidence REAL,
            phishing_probability REAL
        )
    ''')
    
    conn.commit()
    conn.close()

def log_analysis(email_content, subject, sender, result):
    """Log email analysis to database"""
    try:
        conn = sqlite3.connect('phishing_logs.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_logs 
            (email_content, subject, sender, is_phishing, confidence, phishing_probability)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            email_content[:500],  # Truncate content to avoid huge logs
            subject,
            sender,
            1 if result['is_phishing'] else 0,
            result['confidence'],
            result['phishing_probability']
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error logging to database: {e}")
        return False

def get_recent_analyses(limit=10):
    """Get recent analyses from database"""
    try:
        conn = sqlite3.connect('phishing_logs.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, subject, sender, is_phishing, confidence, phishing_probability
            FROM analysis_logs 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"Error fetching from database: {e}")
        return []

def get_statistics():
    """Get analysis statistics"""
    try:
        conn = sqlite3.connect('phishing_logs.db')
        cursor = conn.cursor()
        
        # Total analyses
        cursor.execute('SELECT COUNT(*) FROM analysis_logs')
        total = cursor.fetchone()[0]
        
        # Phishing detections
        cursor.execute('SELECT COUNT(*) FROM analysis_logs WHERE is_phishing = 1')
        phishing = cursor.fetchone()[0]
        
        # Legitimate emails
        legitimate = total - phishing
        
        # Average confidence
        cursor.execute('SELECT AVG(confidence) FROM analysis_logs')
        avg_confidence = cursor.fetchone()[0] or 0
        
        conn.close()
        return {
            'total': total,
            'phishing': phishing,
            'legitimate': legitimate,
            'avg_confidence': round(avg_confidence, 4)
        }
    except Exception as e:
        print(f"Error getting statistics: {e}")
        return {'total': 0, 'phishing': 0, 'legitimate': 0, 'avg_confidence': 0}

@app.route('/')
def index():
    """Main page"""
    stats = get_statistics()
    recent_analyses = get_recent_analyses(5)
    return render_template('index.html', 
                         detector_ready=detector is not None,
                         stats=stats,
                         recent_analyses=recent_analyses)

@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Analyze email for phishing"""
    if detector is None:
        return jsonify({
            'error': 'No trained model available. Please train a model first.'
        }), 400
    
    try:
        # Get form data
        email_content = request.form.get('content', '').strip()
        subject = request.form.get('subject', '').strip()
        sender = request.form.get('sender', '').strip()
        
        # Validate input
        if not email_content:
            return jsonify({'error': 'Email content is required'}), 400
        
        # Make prediction
        result = detector.predict(email_content, subject, sender)
        
        # Log to database
        log_success = log_analysis(email_content, subject, sender, result)
        
        # Add logging status to response
        result['logged'] = log_success
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        print(traceback.format_exc())
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/history')
def history():
    """View analysis history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        analyses = get_recent_analyses(limit)
        return render_template('history.html', analyses=analyses)
    except Exception as e:
        flash(f'Error loading history: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    return jsonify(get_statistics())

@app.route('/train', methods=['GET', 'POST'])
def train_model():
    """Train a new model (basic implementation)"""
    if request.method == 'GET':
        return render_template('train.html')
    
    try:
        # This is a simplified training endpoint
        # In practice, you'd want to upload a dataset file
        flash('Model training is not implemented in this demo. Please use the training script separately.', 'info')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Training failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize database on startup
    init_database()
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)