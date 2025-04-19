from zapv2 import ZAPv2
import time
import json
import os

# Connect to the ZAP API directly
zap = ZAPv2(apikey=None)
zap.baseurl = 'http://127.0.0.1:8080'

target_url = 'http://localhost:5000'

print(f"Starting DAST scan on {target_url}...")

# Spider the target
print("Spidering target...")
scan_id = zap.spider.scan(target_url)
time.sleep(2)

while int(zap.spider.status(scan_id)) < 100:
    print(f"Spider progress: {zap.spider.status(scan_id)}%")
    time.sleep(2)

print("Spider completed.")

# Passive scan (just wait until complete)
print("Waiting for passive scan to complete...")
while int(zap.pscan.records_to_scan) > 0:
    print(f"Records to passive scan: {zap.pscan.records_to_scan}")
    time.sleep(2)

print("Passive scan completed.")

# Start active scan
print("Starting active scan...")
ascan_id = zap.ascan.scan(target_url)

# Wait for the scan to complete
time.sleep(2)

# Check the status of the active scan
scan_status = zap.ascan.status(ascan_id)
print(f"Active scan status: {scan_status}")

while scan_status != '100':
    if scan_status == 'does_not_exist':
        print("Error: Scan ID does not exist. Exiting.")
        break

    print(f"Active scan progress: {scan_status}%")
    time.sleep(5)
    scan_status = zap.ascan.status(ascan_id)

print("Active scan completed.")

# Get alerts
alerts = zap.core.alerts()

# Get the current working directory (where the script was run)
current_directory = os.getcwd()

# Save the alerts to a JSON file in the current directory
json_file_path = os.path.join(current_directory, 'zap_scan_results.json')

with open(json_file_path, 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"\nResults saved to {json_file_path}")
