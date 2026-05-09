import requests
import json
import textwrap

BASE_URL = "http://127.0.0.1:5000"

def print_header(title):
    print("\n" + "="*60)
    print(f"🚀 {title.upper()}")
    print("="*60)

print_header("WELCOME TO ADVANCED PHISHING DETECTOR")
print("Press 1: Scan a URL")
print("Press 2: Scan an Email Text")
print("Press 3: View Dashboard Stats")
print("Press Q: Quit")

while True:
    print("\n" + "-"*60)
    choice = input("👉 Enter your choice (1/2/3/Q): ").strip().upper()

    if choice == 'Q':
        print("Exiting scanner. Good luck for the MLH event!")
        break
        
    elif choice == '3':
        print("\n📊 FETCHING DASHBOARD STATS...")
        try:
            res_stats = requests.get(f"{BASE_URL}/api/stats")
            if res_stats.status_code == 200:
                data = res_stats.json()
                print(f"Total Scans: {data['total_scans']} | Safe: {data['safe_links']} | Phishing: {data['phishing_links']}")
                print(f"🌟 {data['credits']} 🌟")
            else:
                print(f"Stats Error: {res_stats.text}")
        except Exception as e:
            print("Error connecting to server. Is app.py running?")
            
    elif choice == '1':
        user_url = input("🔗 Paste URL to scan: ").strip()
        if user_url:
            print(f"⏳ Scanning URL: {user_url} ...")
            try:
                res = requests.post(f"{BASE_URL}/api/scan", json={"url_to_scan": user_url})
                if res.status_code == 200:
                    result = res.json()
                    print("\n✅ AI RESULT:")
                    print(f"⚠️ Phishing: {result.get('is_phishing')}")
                    print(f"🚨 Threat:   {result.get('threat_level')}")
                    print(f"📝 Reason:   {textwrap.fill(result.get('reason'), width=55)}")
                    print(f"\n🌟 {result.get('credits')} 🌟")
                else:
                    print(f"Error {res.status_code}: {res.text}")
            except Exception as e:
                print("Error connecting to backend.")

    elif choice == '2':
        print("✉️  Paste the email text below (Press Enter twice when done):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        email_text = "\n".join(lines)
        
        if email_text.strip():
            print(f"⏳ Scanning Email Content...")
            try:
                res = requests.post(f"{BASE_URL}/api/scan-email", json={"email_text": email_text})
                if res.status_code == 200:
                    result = res.json()
                    print("\n✅ AI RESULT:")
                    print(f"⚠️ Phishing: {result.get('is_phishing')}")
                    print(f"🚨 Threat:   {result.get('threat_level')}")
                    print(f"📝 Reason:   {textwrap.fill(result.get('reason'), width=55)}")
                    print(f"\n🌟 {result.get('credits')} 🌟")
                else:
                    print(f"Error {res.status_code}: {res.text}")
            except Exception as e:
                print("Error connecting to backend.")
