import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import run_scan
from history.db import init_db, save_scan

EXAMPLE_SITES = ["https://github.com", "https://example.com", "https://www.reddit.com"]


def calculate_score(findings):
    SEVERITY_WEIGHT = {"High": 15, "Medium": 8, "Low": 3, "Info": 0}
    CONFIDENCE_MULTIPLIER = {"High": 1.0, "Medium": 0.6, "Low": 0.3}
    score = 100
    category_counts = {}
    for f in findings:
        base_penalty = SEVERITY_WEIGHT.get(f["severity"], 0)
        confidence_scale = CONFIDENCE_MULTIPLIER.get(f.get("confidence", "High"), 1.0)
        category = f["category"]
        count_so_far = category_counts.get(category, 0)
        diminishing_scale = 1.0 if count_so_far < 2 else 0.5
        category_counts[category] = count_so_far + 1
        score -= base_penalty * confidence_scale * diminishing_scale
    return max(round(score), 0)


if __name__ == "__main__":
    init_db()
    for site in EXAMPLE_SITES:
        print(f"Scanning {site}...")
        findings = run_scan(site)
        score = calculate_score(findings)
        save_scan(site, score, findings)
        print(f"  -> {score}/100, {len(findings)} findings")
    print("Done seeding example scans.")