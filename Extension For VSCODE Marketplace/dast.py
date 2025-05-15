from zapv2 import ZAPv2
import time
import json
import os

# הגדרת כתובת היעד
target_url = "http://localhost:5000"

# יצירת אובייקט ZAP עם proxy ובלי API key
zap = ZAPv2(apikey='', proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

print(f"🚀 Starting DAST scan on {target_url}...")

# פתיחת כתובת היעד כדי להכניס אותה לעץ האתרים של ZAP
zap.urlopen(target_url)
time.sleep(2)

# התחלת Spider Scan
print("🕷 Spidering...")
scan_id = zap.spider.scan(target_url)
time.sleep(2)

while int(zap.spider.status(scan_id)) < 100:
    print(f"Spider progress: {zap.spider.status(scan_id)}%")
    time.sleep(2)

print("✅ Spidering complete.")

# התחלת Active Scan
print("💣 Starting active scan...")
ascan_id = zap.ascan.scan(target_url)
time.sleep(5)

while int(zap.ascan.status(ascan_id)) < 100:
    print(f"Active scan progress: {zap.ascan.status(ascan_id)}%")
    time.sleep(5)

print("✅ Active scan complete.")

# קבלת התראות
print("📋 Fetching alerts...")
alerts = zap.core.alerts(baseurl=target_url)

# יצירת תיקיית UI אם לא קיימת
output_dir = os.path.join(os.path.dirname(__file__), "UI")
os.makedirs(output_dir, exist_ok=True)

# שמירת הפלט כ־JSON
output_path = os.path.join(output_dir, "dast_report.json")
with open(output_path, "w") as f:
    json.dump(alerts, f, indent=2)

print(f"📝 Report written to {output_path}")
