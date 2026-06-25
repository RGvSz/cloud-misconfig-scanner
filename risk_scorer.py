import numpy as np
from sklearn.ensemble import IsolationForest

SEVERITY_WEIGHTS = {
    'CRITICAL': 10,
    'HIGH': 7,
    'MEDIUM': 4,
    'LOW': 1
}

def score_findings(findings):
    for f in findings:
        f['score'] = SEVERITY_WEIGHTS.get(f['severity'], 0)
    return findings

def detect_anomalies(all_findings):
    if len(all_findings) < 2:
        return all_findings

    scores = np.array([[f['score']] for f in all_findings])

    model = IsolationForest(contamination=0.3, random_state=42)
    predictions = model.fit_predict(scores)

    for i, f in enumerate(all_findings):
        f['anomaly'] = predictions[i] == -1

    return all_findings

def flatten_findings(s3_findings, iam_findings, ec2_findings):
    flat = []
    for bucket in s3_findings:
        flat += bucket['findings']
    flat += iam_findings
    flat += ec2_findings
    return flat

def run_scoring(s3_findings, iam_findings, ec2_findings):
    flat = flatten_findings(s3_findings, iam_findings, ec2_findings)
    flat = score_findings(flat)
    flat = detect_anomalies(flat)

    total_score = min(sum(f['score'] for f in flat), 100)

    print("\n[*] Risk Scoring Complete")
    print(f"    Total Risk Score: {total_score}/100")
    for f in flat:
        anomaly_tag = " ⚠ ANOMALY" if f.get('anomaly') else ""
        print(f"    [{f['severity']}] {f['check']}: {f['score']} pts{anomaly_tag}")

    return flat, total_score