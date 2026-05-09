from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import sqlite3
import os
from dotenv import load_dotenv

# .env file se hidden variables load karna
load_dotenv()

# API Key ko safe tarike se nikalna
API_KEY = os.getenv("API_KEY")

# Agar API key miss ho gayi, toh server start hote hi bata dega
if API_KEY:
    print("✅ Success: API Key securely load ho gayi hai!")
else:
    print("❌ FATAL ERROR: API_KEY nahi mili. Apni .env file check karo!")

# Flask app aur CORS setup
app = Flask(__name__)
CORS(app)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            is_phishing BOOLEAN NOT NULL,
            threat_level TEXT NOT NULL,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# App start hone se pehle database setup
init_db()


# --- API 1: URL SCANNER ENDPOINT ---
@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_to_test = data.get('url_to_scan', '')

    if not url_to_test:
        return jsonify({"error": "Bhai, URL bhejna bhool gaye!"}), 400

    # Llama 3.1 ke liye SUPER STRICT prompt 
    prompt = f"""
    Analyze this exact URL: {url_to_test}
    You are a hyper-paranoid cybersecurity expert. You MUST flag the URL as phishing (is_phishing: true) if it shows ANY of these signs:
    1. Brand Impersonation: Uses famous brand names with extra words (e.g., playimdb.com, netflix-update.com, amazon-free.com). The real IMDB is ONLY imdb.com.
    2. Typosquatting: Looks like a real site but has slight typos (e.g., g00gle.com, faceb00k.com).
    3. Suspicious keywords: Contains words like 'free', 'claim', 'winner', 'update', 'login' in the domain.
    
    If it is a clean, well-known, official domain (like exactly https://www.google.com), flag it as safe.
    
    Respond ONLY in valid JSON format exactly like this:
    {{"is_phishing": true or false, "threat_level": "Low/Medium/High", "reason": "Short explanation in English why it is safe or unsafe"}}
    """

    try:
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a cybersecurity AI. Output ONLY valid JSON. No markdown, no extra text."
                },
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }
        
        response = requests.post(api_url, headers=headers, json=payload)
        response_data = response.json()

        if "error" in response_data:
            return jsonify({"error": "Groq API Error", "details": response_data["error"]}), 500

        ai_text = response_data['choices'][0]['message']['content']
        result_json = json.loads(ai_text)

        is_phishing = result_json.get('is_phishing', False)
        threat_level = result_json.get('threat_level', 'Unknown')
        reason = result_json.get('reason', 'No reason provided by AI.')

        # --- NAYA DATABASE LOGIC (No Duplicates) ---
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check karna ki URL pehle se database mein hai ya nahi
        cursor.execute('SELECT id FROM scans WHERE url = ?', (url_to_test,))
        existing_record = cursor.fetchone()

        if existing_record:
            # Agar pehle se hai, toh sirf details update karo (Duplicate nahi banega)
            cursor.execute('''
                UPDATE scans 
                SET is_phishing = ?, threat_level = ?, reason = ?, timestamp = CURRENT_TIMESTAMP
                WHERE url = ?
            ''', (is_phishing, threat_level, reason, url_to_test))
        else:
            # Agar naya URL hai, toh naya record insert karo
            cursor.execute('''
                INSERT INTO scans (url, is_phishing, threat_level, reason) 
                VALUES (?, ?, ?, ?)
            ''', (url_to_test, is_phishing, threat_level, reason))
            
        conn.commit()
        conn.close()

        # Frontend (Sruthika) ko answer bhejna
        return jsonify({
            "is_phishing": is_phishing,
            "threat_level": threat_level,
            "reason": reason
        })
        
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500


# --- API 2: DASHBOARD STATS ENDPOINT ---
@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scans WHERE is_phishing = 1')
        phishing_count = cursor.fetchone()[0]
        
        safe_count = total_scans - phishing_count

        cursor.execute('SELECT url, is_phishing, threat_level FROM scans ORDER BY timestamp DESC LIMIT 5')
        recent_scans = [{"url": row[0], "is_phishing": bool(row[1]), "threat_level": row[2]} for row in cursor.fetchall()]
        
        conn.close()

        return jsonify({
            "total_scans": total_scans,
            "safe_links": safe_count,
            "phishing_links": phishing_count,
            "recent_activity": recent_scans
        })
    except Exception as e:
        return jsonify({"error": "Database error: " + str(e)}), 500


if __name__ == '__main__':
    print("🚀 Tumhara Next-Level Groq AI Server chalu ho gaya hai!")
    app.run(debug=True, port=5000)
