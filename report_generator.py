from datetime import datetime, timezone

SEVERITY_COLORS = {
    'CRITICAL': '#ff4444',
    'HIGH': '#ff8800',
    'MEDIUM': '#ffcc00',
    'LOW': '#00cc44'
}

def generate_html_report(s3_findings, iam_findings, ec2_findings, flat_findings, risk_score):
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"

    critical = sum(1 for f in flat_findings if f['severity'] == 'CRITICAL')
    high     = sum(1 for f in flat_findings if f['severity'] == 'HIGH')
    medium   = sum(1 for f in flat_findings if f['severity'] == 'MEDIUM')
    low      = sum(1 for f in flat_findings if f['severity'] == 'LOW')
    anomalies = sum(1 for f in flat_findings if f.get('anomaly'))

    rows = ""
    for f in flat_findings:
        color = SEVERITY_COLORS.get(f['severity'], '#ffffff')
        anomaly = " ANOMALY" if f.get('anomaly') else ""
        rows += f"""
        <tr>
            <td style="color:{color};font-weight:bold">{f['severity']}</td>
            <td>{f['check']}</td>
            <td>{f['detail']}</td>
            <td>{f['score']}</td>
            <td style="color:#ff8800">{anomaly}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Cloud Misconfiguration Report</title>
    <style>
        body {{ font-family: monospace; background: #0d0d0d; color: #e0e0e0; padding: 30px; }}
        h1 {{ color: #00ff99; }}
        h2 {{ color: #00ccff; border-bottom: 1px solid #333; padding-bottom: 5px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ background: #1a1a1a; padding: 15px 25px; border-radius: 8px; text-align: center; }}
        .card .value {{ font-size: 2em; font-weight: bold; }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff8800; }}
        .medium {{ color: #ffcc00; }}
        .low {{ color: #00cc44; }}
        .score {{ color: #00ff99; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #1a1a1a; color: #00ccff; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #222; }}
        tr:hover {{ background: #1a1a1a; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Cloud Misconfiguration Scanner</h1>
    <p class="timestamp">Scan Time: {timestamp}</p>

    <h2>Summary</h2>
    <div class="summary">
        <div class="card"><div class="value score">{risk_score}/100</div><div>Risk Score</div></div>
        <div class="card"><div class="value critical">{critical}</div><div>CRITICAL</div></div>
        <div class="card"><div class="value high">{high}</div><div>HIGH</div></div>
        <div class="card"><div class="value medium">{medium}</div><div>MEDIUM</div></div>
        <div class="card"><div class="value low">{low}</div><div>LOW</div></div>
        <div class="card"><div class="value high">{anomalies}</div><div>ANOMALIES</div></div>
    </div>

    <h2>Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Check</th>
            <th>Detail</th>
            <th>Score</th>
            <th>Anomaly</th>
        </tr>
        {rows}
    </table>
</body>
</html>"""

    with open(filename, 'w') as f:
        f.write(html)

    return filename