import argparse
import json
from html_report import html
from datetime import datetime


def get_severity(failed_attempts):

    if failed_attempts <= 2:
        return "LOW"

    elif failed_attempts <= 4:
        return "MEDIUM"

    else:
        return "HIGH"

# Counters
successful_logins = 0
failed_logins = 0

# Store failed login timestamps for each IP
failed_by_ip = {}

# Store all login events for each IP
events_by_ip = {}

# Store security alerts
alerts = []


# Read the security log
with open("SecurityLogAnalyzer\Logs\Security.log", "r") as file:
    for line in file:

        # Break log line into parts
        parts = line.strip().split()

        # Extract information
        date = parts[0]
        time = parts[1]
        user = parts[2].split("=")[1]
        ip = parts[3].split("=")[1]
        event = parts[4].split("=")[1]

        # Convert date and time into datetime object
        timestamp = datetime.strptime(
            date + " " + time,
            "%Y-%m-%d %H:%M:%S"
        )

        # Store every event for each IP
        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append({
            "timestamp": timestamp,
            "user": user,
            "event": event
        })

        # Count successful logins
        if event == "LOGIN_SUCCESS":

            successful_logins += 1

        # Count failed logins
        elif event == "LOGIN_FAILED":

            failed_logins += 1

            # Store failed login timestamp
            if ip not in failed_by_ip:
                failed_by_ip[ip] = []

            failed_by_ip[ip].append(timestamp)


# Display login statistics
print("================================")
print("       SECURITY LOG ANALYZER")
print("================================")

print("Successful Logins:", successful_logins)
print("Failed Logins:", failed_logins)


# --------------------------------
# Brute Force Detection
# --------------------------------

for ip, timestamps in failed_by_ip.items():

    timestamps.sort()

    for i in range(len(timestamps)):

        count = 1

        for j in range(i + 1, len(timestamps)):

            time_difference = timestamps[j] - timestamps[i]

            if time_difference.total_seconds() <= 300:
                count += 1
            else:
                break

        if count >= 5:

            alert = {
                "type": "Brute Force Attack",
                "ip": ip,
                "failed_attempts": count,
                "time_window": "5 minutes",
                "severity": "HIGH"
            }

            alerts.append(alert)

            break


# --------------------------------
# Failed → Successful Login Detection
# --------------------------------

for ip, events in events_by_ip.items():

    events.sort(key=lambda x: x["timestamp"])

    failed_count = 0

    for event_data in events:

        if event_data["event"] == "LOGIN_FAILED":

            failed_count += 1

        elif event_data["event"] == "LOGIN_SUCCESS":

            if failed_count >= 3:

                alert = {
                    "type": "Suspicious Authentication Pattern",
                    "ip": ip,
                    "user": event_data["user"],
                    "failed_attempts": failed_count,
                    "event": "FAILED → SUCCESS",
                    "severity": "HIGH"
                }

                alerts.append(alert)

            failed_count = 0


# --------------------------------
# Display Alerts
# --------------------------------

print("\n================================")
print("         SECURITY ALERTS")
print("================================")

if len(alerts) == 0:

    print("No suspicious activity detected.")

else:

    for alert in alerts:

        print("\n🚨 ALERT")
        print("Type:", alert["type"])
        print("IP:", alert["ip"])

        if "user" in alert:
            print("User:", alert["user"])

        print("Severity:", alert["severity"])

        if "failed_attempts" in alert:
            print("Failed Attempts:", alert["failed_attempts"])

        if "time_window" in alert:
            print("Time Window:", alert["time_window"])

        if "event" in alert:
            print("Pattern:", alert["event"])

        print("--------------------------------")


    alert = {
    "type": "Brute Force",
    "ip": ip,
    "failed_attempts": count,
    "severity": "HIGH"
}

alerts.append(alert)
with open("SecurityLogAnalyzer/reports/report.json", "w") as file:
    json.dump(alerts, file, indent=4)