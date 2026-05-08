from flask import Flask, request, jsonify
from flask_cors import CORS
import requests  # <-- Direct web request
import json
import sqlite3

# Flask app aur CORS setup karna
app = Flask(__name__)
CORS(app)

# ==========================================
# 🛑 SECURITY WARNING: Yahan apni GROQ API KEY daalna
# ==========================================
GROQ_API_KEY = "YOUR_API_KEY"

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

# App start hone se pehle database check/create karna
init_db()


# --- API 1: URL SCANNER ENDPOINT ---
@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_to_test = data.get('url_to_scan', '')

    if not url_to_test:
        return jsonify({"error": "Bhai, URL bhejna bhool gaye!"}), 400

    # Llama 3.1 ke liye SUPER STRICT prompt (Advanced Pattern Matching)
    prompt = f"""
    Analyze this URL: {url_to_test}
    You must flag the URL as phishing if it shows any of these signs:
    1. Typosquatting (e.g., g00gle.com instead of google.com).
    2. Brand Impersonation (e.g., playimdb.com, netflix-free-update.com, secure-paypal-login.com).
    3. Suspicious keywords like 'free', 'winner', 'claim', 'update', 'play' attached to popular brand names.
    4. Unusually long strings or weird subdomains.
    
    Respond ONLY in valid JSON format exactly like this:
    {{"is_phishing": true or false, "threat_level": "Low/Medium/High", "reason": "Short explanation in English why it is safe or unsafe"}}
    """

    try:
        # 🚀 THE ULTIMATE FIX: Using stable Groq API with Llama-3.1
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        # Groq payload with JSON forcing aur NAYA MODEL
        payload = {
            "model": "llama-3.1-8b-instant", # Naya super fast and smart model
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a hyper-paranoid cybersecurity expert analyzing links for a Hackathon project. If a domain mimics a popular brand but isn't the exact official domain, flag it as phishing. Output only JSON."
                },
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"} # Force valid JSON
        }
        
        # Direct Groq Server par hit marna
        response = requests.post(api_url, headers=headers, json=payload)
        response_data = response.json()

        # Error handling for invalid API keys or limits
        if "error" in response_data:
            return jsonify({"error": "Groq API Error", "details": response_data["error"]}), 500

        # AI ka exact text nikalna
        ai_text = response_data['choices'][0]['message']['content']
        
        # Parse the JSON response
        result_json = json.loads(ai_text)

        # Ensure we always have these keys
        is_phishing = result_json.get('is_phishing', False)
        threat_level = result_json.get('threat_level', 'Unknown')
        reason = result_json.get('reason', 'No reason provided by AI.')

        # Result ko apne Database mein save karna
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (url, is_phishing, threat_level, reason) VALUES (?, ?, ?, ?)',
            (url_to_test, is_phishing, threat_level, reason)
        )
        conn.commit()
        conn.close()

        # Sruthika ke frontend ko answer wapas bhejna
        return jsonify({
            "is_phishing": is_phishing,
            "threat_level": threat_level,
            "reason": reason
        })
        
    except json.JSONDecodeError as je:
         return jsonify({"error": "AI response was not valid JSON", "details": str(je), "raw_response": ai_text}), 500
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500


# --- API 2: DASHBOARD STATS ENDPOINT (PRO FEATURE) ---
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