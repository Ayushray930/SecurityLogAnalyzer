import json


# Read JSON report
with open("SecurityLogAnalyzer/reports/report.json", "r") as file:
    alerts = json.load(file)


html = """
<!DOCTYPE html>
<html>
<head>

    <title>Security Log Analyzer</title>

    <style>

        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            padding: 30px;
        }

        h1 {
            text-align: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
        }

        th, td {
            border: 1px solid black;
            padding: 10px;
        }

        th {
            background-color: #333;
            color: white;
        }

    </style>

</head>

<body>

<h1>Security Log Analyzer Report</h1>

<table>

<tr>
    <th>Type</th>
    <th>IP Address</th>
    <th>User</th>
    <th>Failed Attempts</th>
    <th>Severity</th>
</tr>
"""


for alert in alerts:

    html += f"""
    <tr>

        <td>{alert.get("type", "N/A")}</td>

        <td>{alert.get("ip", "N/A")}</td>

        <td>{alert.get("user", "N/A")}</td>

        <td>{alert.get("failed_attempts", "N/A")}</td>

        <td>{alert.get("severity", "N/A")}</td>

    </tr>
    """


html += """

</table>

</body>
</html>
"""


# Create HTML reports
with open("SecurityLogAnalyzer/reports/security_report.html", "w", encoding="utf-8") as file:

    file.write(html)


print("HTML report generated successfully!")