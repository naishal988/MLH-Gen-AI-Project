# 🛡️ PhishGuard ZK: Privacy-Preserving AI Threat Detector 

An advanced, Zero-Knowledge & Zero-Trust Phishing Detection Engine built specifically for the **MLH Midnight Hackathon (May 2026)**. 

🎯 **Targeting the AI Track:** Building powerful AI threat detection without ever exposing the underlying sensitive user data.

### 🌟 Live Demo
https://phishguard-ai-mlh.netlify.app/

### 🚀 Key Features
* **Zero-Knowledge Privacy Shield:** Original URLs and Emails are NEVER stored on our database. The server instantly scrubs the data and generates a cryptographic SHA-256 Hash to ensure 100% user privacy.
* **Midnight Blockchain Architecture:** Designed to log threat hashes securely using Midnight's `Compact` smart contract language, ensuring data is verifiable but totally blind.
* **Hyper-Paranoid Threat Hunting:** AI detects root domain impersonation, typosquatting, and social engineering attempts in real-time.
* **Anonymized Dashboard:** The dashboard tracks safe links and phishing attempts dynamically using secure ZK-proof hashes instead of raw, sensitive user data.

### 💻 Tech Stack
* **Backend:** Python, Flask, SQLite, SHA-256 Cryptography (Developed by Naishal)
* **Frontend:** HTML5, CSS3, Vanilla JS, Chart.js (Developed by Sruthika)
* **AI Engine:** Groq API (Llama 3.1 8B Instant) with Temperature 0.0 for deterministic analysis.
* **Web3 Integration:** Midnight 'Compact' Smart Contract Architecture.
* **Deployment:** Render (Backend) & Netlify (Frontend)

### ⚙️ How The Privacy Architecture Works
1. **The Scan:** A user inputs a suspicious URL or Private Email. It is temporarily analyzed by our deterministic Llama-3 model.
2. **The Scrub:** The moment the AI returns a Threat Level verdict, the original raw data is permanently deleted from server memory.
3. **The Hash & Log:** A secure cryptographic hash is generated. This hash is what gets stored in our database and is designed to be logged on the Midnight ledger (`midnight_ledger.compact`), keeping the actual user data completely confidential.

---
*Built with ❤️ for a safer, private web by Naishal & Sruthika*
