import requests
import json

BASE_URL = "http://127.0.0.1:5000"

print("="*50)
print("🚀 WELCOME TO PHISHING DETECTOR TERMINAL")
print("="*50)

while True:
    print("\n" + "-"*50)
    # USER SE DYNAMIC INPUT LENA
    user_url = input("👉 Enter URL to scan (or type 'q' to quit, 's' for stats): ").strip()

    if user_url.lower() == 'q':
        print("Exiting scanner. Good luck for the MLH event!")
        break
        
    elif user_url.lower() == 's':
        # Dashboard Stats check karna
        print("\n📊 FETCHING DASHBOARD STATS...")
        try:
            res_stats = requests.get(f"{BASE_URL}/api/stats")
            if res_stats.status_code == 200:
                print(json.dumps(res_stats.json(), indent=4))
            else:
                print(f"Stats Error: {res_stats.text}")
        except Exception as e:
            print("Error connecting to server. Is app.py running?")
            
    elif user_url != "":
        # URL ko Backend par bhejna
        print(f"⏳ Scanning: {user_url} ...")
        payload = {"url_to_scan": user_url}
        
        try:
            res = requests.post(f"{BASE_URL}/api/scan", json=payload)
            if res.status_code == 200:
                result = res.json()
                print("\n✅ AI RESULT:")
                print(f"Phishing: {result.get('is_phishing')}")
                print(f"Threat:   {result.get('threat_level')}")
                print(f"Reason:   {result.get('reason')}")
            else:
                print(f"Error {res.status_code}: {res.text}")
        except Exception as e:
            print("Error connecting to backend. Is app.py running?")