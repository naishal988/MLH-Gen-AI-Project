from flask import Flask, request, jsonify
from flask_cors import CORS
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

    # 🚀 SMART TIER-1 SOC PROMPT (Balances Zero-Trust with Common Sense)
    prompt = f"""
    Analyze this exact URL: {url_to_test}
    You are an elite, Tier-1 SOC Threat Hunter. You must balance strict ZERO-TRUST with logical common sense to avoid false positives on legitimate sites.

    First, internally parse the URL into Subdomain, Root Domain, TLD, and Path. IGNORE 'https://', 'http://', and 'www.'.
    
    APPLY THESE EXPERT RULES STRICTLY:
    1. LEGITIMATE SUBDOMAINS ARE SAFE: Official subdomains of massive global brands are SAFE. (e.g., 'web.whatsapp.com' is the official WhatsApp web client, 'drive.google.com' is safe). Do NOT flag legitimate subdomains as root domain impersonation.
    2. EDUCATIONAL & INSTITUTIONAL EXCEPTION: Domains ending in strictly '.ac.in', '.edu', or '.edu.in' belong to legitimate universities and academic institutions (e.g., silveroakuni.ac.in). These are SAFE and highly trusted.
    3. LOGIN PAGES ARE NORMAL ON REAL SITES: Having '/login', 'login.aspx', 'auth', or 'portal' in the URL path is 100% NORMAL and SAFE *IF* the root domain is a legitimate university, bank, or known service. Only flag 'login' keywords if the root domain itself is a cheap scam domain.
    4. ROOT DOMAIN IMPERSONATION (CRITICAL THREAT): If the root domain merges a brand name with other words directly (e.g., 'playimdb.com', 'whatsapp-login-free.com'), it is 100% PHISHING.
    5. GOVERNMENT SPOOFING: Any domain implying Indian government services (words like gov, nra, yojana) MUST end in exactly '.gov.in' or '.nic.in'. If it uses '.in', '.com', '.online', it is a High-Threat SCAM.
    6. FREE HOSTING & GIBBERISH: Domains on 'blogspot.com' offering 'free' stuff, or domains with random unverified gibberish strings (e.g., 'sajks.com') are phishing.
    
    Evaluate carefully: Is the root domain actually a known legitimate entity (like whatsapp.com or a valid university)? If yes, mark is_phishing as false.

    Respond ONLY in valid JSON format exactly like this:
    {{"is_phishing": true or false, "threat_level": "Low/Medium/High", "reason": "Short, expert technical explanation of the verdict"}}
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
            return jsonify({"error": "Groq API Error", "details": response_data["error"]}), 500

        ai_text = response_data['choices'][0]['message']['content']
        result_json = json.loads(ai_text)

        is_phishing = result_json.get('is_phishing', False)
        threat_level = result_json.get('threat_level', 'Unknown')
        reason = result_json.get('reason', 'No reason provided by AI.')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM scans WHERE url = ?', (url_to_test,))
        if cursor.fetchone():
            cursor.execute('''UPDATE scans SET is_phishing = ?, threat_level = ?, reason = ?, timestamp = CURRENT_TIMESTAMP WHERE url = ?''', (is_phishing, threat_level, reason, url_to_test))
        else:
            cursor.execute('''INSERT INTO scans (url, is_phishing, threat_level, reason) VALUES (?, ?, ?, ?)''', (url_to_test, is_phishing, threat_level, reason))
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
            "temperature": 0.0
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
