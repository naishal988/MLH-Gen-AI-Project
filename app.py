from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import requests
import json
import sqlite3
import os
from dotenv import load_dotenv

# .env file se hidden variables load karna
load_dotenv()

API_KEY = os.getenv("API_KEY")

if API_KEY:
    print("✅ Success: API Key securely load ho gayi hai!")
else:
    print("❌ FATAL ERROR: API_KEY nahi mili. Apni .env file check karo!")

app = Flask(__name__)
CORS(app)

PROJECT_CREDITS = "Made by Naishal (Backend) & Sruthika (Frontend) | MLH Midnight Hackathon"

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Nayi privacy table banayenge
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS privacy_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zk_data_hash TEXT NOT NULL,       
            is_phishing BOOLEAN NOT NULL,
            threat_level TEXT NOT NULL,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ==========================================
# API 1: URL SCANNER ENDPOINT (Zero-Knowledge)
# ==========================================
@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_to_test = data.get('url_to_scan', '')

    if not url_to_test:
        return jsonify({"error": "Bhai, URL bhejna bhool gaye!"}), 400

    # 🛡️ PRIVACY SHIELD: Generate Hash of URL
    zk_hash = hashlib.sha256(url_to_test.encode('utf-8')).hexdigest()

    # 🚀 FIXED PROMPT (Balanced Zero-Trust with Common Sense)
    prompt = f"""
    Analyze this exact URL: {url_to_test}
    You are an expert Cybersecurity AI Threat Hunter. You must balance Zero-Trust security with logical common sense to avoid false positives on legitimate platforms.

    First, internally parse the URL into Subdomain, Root Domain, TLD, and Path. IGNORE standard prefixes like 'https://'. 
    
    APPLY THESE RULES STRICTLY IN THIS ORDER:
    1. GLOBAL WHITELIST (100% SAFE): If the root domain is exactly 'whatsapp.com', 'google.com', 'devpost.com', 'github.com', 'youtube.com', or 'netlify.app', it is strictly SAFE (is_phishing: false). Subdomains like 'web.whatsapp.com' or 'gemini.google.com' are also strictly SAFE.
    2. EDUCATIONAL EXCEPTION (100% SAFE): Any domain ending in '.ac.in', '.edu', or '.edu.in' belongs to a legitimate educational institution (e.g., silveroakuni.ac.in). Treat these as strictly SAFE.
    3. PROJECT WHITELIST (100% SAFE): If the URL contains 'phishguard', it is our own hackathon app and is SAFE.
    4. ROOT DOMAIN IMPERSONATION (THREAT): If the root domain merges a brand name with other words directly (e.g., 'playimdb.com', 'whatsapp-login-free.com'), it is 100% PHISHING. 
    5. GOVERNMENT SPOOFING (THREAT): Any domain implying Indian government services MUST end in exactly '.gov.in', '.nic.in'. If it uses '.in', '.com', '.online', it is a High-Threat SCAM.
    6. FREE HOSTING & GIBBERISH (THREAT): Domains on 'blogspot.com' offering 'free' stuff, or random unverified gibberish root domains (e.g., 'sajks.com') are PHISHING.

    Respond ONLY in valid JSON format exactly like this:
    {{"is_phishing": true or false, "threat_level": "Low/Medium/High", "reason": "Short, expert technical explanation"}}
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
            "temperature": 0.0  
        }
        
        response = requests.post(api_url, headers=headers, json=payload)
        response_data = response.json()

        if "error" in response_data:
            return jsonify({"error": " API Error", "details": response_data["error"]}), 500

        ai_text = response_data['choices'][0]['message']['content']
        result_json = json.loads(ai_text)

        is_phishing = result_json.get('is_phishing', False)
        threat_level = result_json.get('threat_level', 'Unknown')
        reason = result_json.get('reason', 'No reason provided by AI.')

        # Database me URL ki jagah sirf HASH save hoga
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM privacy_scans WHERE zk_data_hash = ?', (zk_hash,))
        if cursor.fetchone():
            cursor.execute('''UPDATE privacy_scans SET is_phishing = ?, threat_level = ?, reason = ?, timestamp = CURRENT_TIMESTAMP WHERE zk_data_hash = ?''', (is_phishing, threat_level, reason, zk_hash))
        else:
            cursor.execute('''INSERT INTO privacy_scans (zk_data_hash, is_phishing, threat_level, reason) VALUES (?, ?, ?, ?)''', (zk_hash, is_phishing, threat_level, reason))
        conn.commit()
        conn.close()

        return jsonify({
            "is_phishing": is_phishing,
            "threat_level": threat_level,
            "reason": reason,
            "zk_proof_hash": zk_hash,
            "privacy_status": "Secure. Original URL scrubbed from server.",
            "credits": PROJECT_CREDITS
        })
        
    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500


# ==========================================
# API 2: EMAIL TEXT SCANNER ENDPOINT (Zero-Knowledge)
# ==========================================
@app.route('/api/scan-email', methods=['POST'])
def scan_email():
    data = request.json
    email_text = data.get('email_text', '')

    if not email_text:
        return jsonify({"error": "Email content empty hai!"}), 400

    # 🛡️ PRIVACY SHIELD: Generate Hash of Email
    zk_hash = hashlib.sha256(email_text.encode('utf-8')).hexdigest()

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
            "temperature": 0.0
        }
        
        response = requests.post(api_url, headers=headers, json=payload)
        response_data = response.json()
        
        if "error" in response_data:
            return jsonify({"error": " API Error", "details": response_data["error"]}), 500
            
        ai_text = response_data['choices'][0]['message']['content']
        result_json = json.loads(ai_text)
        
        is_phishing = result_json.get('is_phishing', False)
        threat_level = result_json.get('threat_level', 'Unknown')
        reason = result_json.get('reason', 'No reason provided by AI.')

        # Database me Email ki jagah sirf HASH save hoga
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM privacy_scans WHERE zk_data_hash = ?', (zk_hash,))
        if cursor.fetchone():
            cursor.execute('''UPDATE privacy_scans SET is_phishing = ?, threat_level = ?, reason = ?, timestamp = CURRENT_TIMESTAMP WHERE zk_data_hash = ?''', (is_phishing, threat_level, reason, zk_hash))
        else:
            cursor.execute('''INSERT INTO privacy_scans (zk_data_hash, is_phishing, threat_level, reason) VALUES (?, ?, ?, ?)''', (zk_hash, is_phishing, threat_level, reason))
        conn.commit()
        conn.close()

        return jsonify({
            "is_phishing": is_phishing,
            "threat_level": threat_level,
            "reason": reason,
            "zk_proof_hash": zk_hash,
            "privacy_status": "Secure. Original Email text scrubbed from server.",
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
        
        # Count queries ab privacy table se
        cursor.execute('SELECT COUNT(*) FROM privacy_scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM privacy_scans WHERE is_phishing = 1')
        phishing_count = cursor.fetchone()[0]
        
        safe_count = total_scans - phishing_count
        
        # Recent scans ke liye ab URL ki jagah ZK Hash bhejna hai (taaki dashboard pe hashes dikhein)
        cursor.execute('SELECT zk_data_hash, is_phishing, threat_level FROM privacy_scans ORDER BY timestamp DESC LIMIT 5')
        # Frontend pe lamba hash kachra na lage isliye usko thoda truncate (short) karke bhej rahe hain UI ke liye
        recent_scans = [{"url": f"{row[0][:12]}... (Secured)", "is_phishing": bool(row[1]), "threat_level": row[2]} for row in cursor.fetchall()]
        
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
    print("🚀 Tumhara Privacy-Preserving ZK Server chalu ho gaya hai!")
    app.run(debug=True, port=5000)
