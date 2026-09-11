from flask import Flask, render_template, request, send_file

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import run_scan
from report.pdf_report import generate_pdf_report
from history.db import init_db, save_scan, get_all_scans, get_scan_by_id, get_previous_scan

app = Flask(__name__)
init_db()

_last_scan_time = {"timestamp": 0}
SCAN_COOLDOWN_SECONDS = 60

SEVERITY_WEIGHT = {"High": 15, "Medium": 8, "Low": 3, "Info": 0}
CONFIDENCE_MULTIPLIER = {"High": 1.0, "Medium": 0.6, "Low": 0.3}


def calculate_score(findings):
    score = 100
    category_counts = {}
    for f in findings:
        base_penalty = SEVERITY_WEIGHT.get(f["severity"], 0)
        confidence_scale = CONFIDENCE_MULTIPLIER.get(f.get("confidence", "High"), 1.0)
        category = f["category"]
        count_so_far = category_counts.get(category, 0)
        diminishing_scale = 1.0 if count_so_far < 2 else 0.5
        category_counts[category] = count_so_far + 1
        penalty = base_penalty * confidence_scale * diminishing_scale
        score -= penalty
    return max(round(score), 0)


@app.route("/", methods=["GET", "POST"])
def index():
    all_results = []
    url = ""
    error_message = None

    if request.method == "POST":
        now = time.time()
        if now - _last_scan_time["timestamp"] < SCAN_COOLDOWN_SECONDS:
            error_message = "Please wait a bit before scanning again."
        else:
            _last_scan_time["timestamp"] = now
            raw_input = request.form.get("urls", "").strip()
            url = raw_input
            url_list = [u.strip() for u in raw_input.splitlines() if u.strip()]

            for single_url in url_list:
                if not single_url.startswith("http"):
                    single_url = "https://" + single_url
                results = run_scan(single_url)
                score = calculate_score(results)
                new_id = save_scan(single_url, score, results)
                previous = get_previous_scan(single_url, exclude_id=new_id)
                all_results.append({
                    "url": single_url,
                    "score": score,
                    "results": results,
                    "previous_score": previous["score"] if previous else None,
                })

    return render_template("index.html", all_results=all_results, url=url, error_message=error_message)


@app.route("/history")
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)


@app.route("/history/<int:scan_id>")
def history_detail(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return "Scan not found", 404
    previous = get_previous_scan(scan["url"], exclude_id=scan["id"])
    all_results = [{
        "url": scan["url"],
        "score": scan["score"],
        "results": scan["findings"],
        "previous_score": previous["score"] if previous else None,
    }]
    return render_template("index.html", all_results=all_results, url=scan["url"], error_message=None)


@app.route("/download-report")
def download_report():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400
    results = run_scan(url)
    score = calculate_score(results)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(project_root, "report", "latest_report.pdf")
    generate_pdf_report(url, score, results, output_path)
    return send_file(output_path, as_attachment=True, download_name="security_report.pdf")


@app.route("/examples")
def examples():
    all_scans = get_all_scans()
    example_urls = {"https://github.com", "https://example.com", "https://www.reddit.com"}
    example_scans = [s for s in all_scans if s["url"] in example_urls]

    seen = set()
    unique_scans = []
    for s in example_scans:
        if s["url"] not in seen:
            unique_scans.append(s)
            seen.add(s["url"])

    all_results = []
    for s in unique_scans:
        previous = get_previous_scan(s["url"], exclude_id=s["id"])
        all_results.append({
            "url": s["url"],
            "score": s["score"],
            "results": s["findings"],
            "previous_score": previous["score"] if previous else None,
        })

    return render_template("index.html", all_results=all_results, url="", error_message=None)


if __name__ == "__main__":
    app.run(debug=True, port=5000)