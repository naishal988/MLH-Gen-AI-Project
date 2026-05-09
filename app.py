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

# Har API response ke end mein yeh add hoga
PROJECT_CREDITS = "Made by Naishal (Backend Developer) & Sruthika (Frontend Developer)"

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


# ==========================================
# API 1: URL SCANNER ENDPOINT
# ==========================================
@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_to_test = data.get('url_to_scan', '')

    if not url_to_test:
        return jsonify({"error": "Bhai, URL bhejna bhool gaye!"}), 400

    # 🚀 IMPROVED STRICT PROMPT (Added Govt Spoofing Rule)
    prompt = f"""
    Analyze this exact URL: {url_to_test}
    You are an elite, Tier-1 SOC Threat Hunter and Cybersecurity Expert operating on a strict ZERO-TRUST policy. Your logic must be flawless. Do not hallucinate or assume legitimacy.

    First, internally parse the URL into Subdomain, Root Domain, and TLD. 
    
    APPLY THESE GOD-LEVEL RULES STRICTLY:
    1. ROOT DOMAIN IMPERSONATION (CRITICAL): The official root domain is the core identity. E.g., for IMDB, it is exactly 'imdb.com'. If the root domain merges the brand name with other words directly (e.g., 'playimdb.com', 'google-support.com', 'amazonfree.com'), it is 100% PHISHING. Real companies use subdomains (e.g., 'play.imdb.com'), NOT modified root domains.
    2. GOVERNMENT SPOOFING (NO EXCEPTIONS): Any domain implying government services (words like gov, nra, yojana, excise, uidai, police) MUST end in exactly '.gov.in', '.nic.in', or '.gov'. If it uses '.in', '.com', '.online', '.org', it is a High-Threat SCAM.
    3. FREE HOSTING & SCAM KEYWORDS: Domains on 'blogspot.com', 'wordpress.com', or using keywords like 'free', 'claim', 'winner', 'register', 'login' are SCAMS.
    4. GIBBERISH/OBSCURE DOMAINS: If the root domain is a random string (e.g., 'sajks.com') or unverified acronyms (e.g., 'kvms.org.in'), flag it as phishing. Scammers use cheap domains. Do not assume it is a legitimate local business.
    
    DEVIATION RULE: Only output {{"is_phishing": false}} if the domain is EXACTLY a globally recognized, unmodified root domain (like exactly 'google.com', 'youtube.com'). If there is even 1% deviation, flag it as true.

    Respond ONLY in valid JSON format exactly like this:
    {{"is_phishing": true or false, "threat_level": "Low/Medium/High", "reason": "Short, expert technical explanation of the specific threat vector identified (e.g., Root Domain Impersonation, Typosquatting)"}}
    """

    try:
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
        
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity AI. Output ONLY valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0  # <-- AI creativity disabled for consistent answers
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

        # Database No-Duplicate Logic
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM scans WHERE url = ?', (url_to_test,))
        if cursor.fetchone():
            cursor.execute('''
                UPDATE scans 
                SET is_phishing = ?, threat_level = ?, reason = ?, timestamp = CURRENT_TIMESTAMP 
                WHERE url = ?
            ''', (is_phishing, threat_level, reason, url_to_test))
        else:
            cursor.execute('''
                INSERT INTO scans (url, is_phishing, threat_level, reason) 
                VALUES (?, ?, ?, ?)
            ''', (url_to_test, is_phishing, threat_level, reason))
        conn.commit()
        conn.close()

        return jsonify({
            "is_phishing": is_phishing,
            "threat_level": threat_level,
            "reason": reason,
            "credits": PROJECT_CREDITS
        })
        
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500


# ==========================================
# API 2: EMAIL TEXT SCANNER ENDPOINT 
# ==========================================
@app.route('/api/scan-email', methods=['POST'])
def scan_email():
    data = request.json
    email_text = data.get('email_text', '')

    if not email_text:
        return jsonify({"error": "Email content empty hai!"}), 400

    prompt = f"""
    Analyze this email content for social engineering and phishing attempts:
    "{email_text}"
    
    Check for:
    1. Unnecessary urgency or threats (e.g., "Your account will be suspended").
    2. Requests for sensitive info (passwords, OTPs, bank details).
    3. Phishing tone or too-good-to-be-true offers (lotteries, free money).
    
    Respond ONLY in valid JSON format exactly like this:
    {{"is_phishing": true or false, "threat_level": "Low/Medium/High", "reason": "Short explanation in English"}}
    """

    try:
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
        
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": "You are an expert email security AI. Output ONLY valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0 # <-- Consistency for emails too
        }
        
        response = requests.post(api_url, headers=headers, json=payload)
        response_data = response.json()
        
        if "error" in response_data:
            return jsonify({"error": "Groq API Error", "details": response_data["error"]}), 500
            
        ai_text = response_data['choices'][0]['message']['content']
        result_json = json.loads(ai_text)

        return jsonify({
            "is_phishing": result_json.get('is_phishing', False),
            "threat_level": result_json.get('threat_level', 'Unknown'),
            "reason": result_json.get('reason', 'No reason provided.'),
            "credits": PROJECT_CREDITS
        })
        
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500


# ==========================================
# API 3: DASHBOARD STATS ENDPOINT
# ==========================================
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
            "recent_activity": recent_scans,
            "credits": PROJECT_CREDITS
        })
    except Exception as e:
        return jsonify({"error": "Database error: " + str(e)}), 500


if __name__ == '__main__':
    print("🚀 Tumhara Next-Level Groq AI Server chalu ho gaya hai!")
    app.run(debug=True, port=5000)
