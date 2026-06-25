from flask import Flask, request, render_template, redirect, url_for
import subprocess
import os
import time
import json
from datetime import datetime

app = Flask(__name__)

RESULTS_DIR = "results"
HISTORY_FILE = os.path.join(RESULTS_DIR, "history.json")
NUCLEI_TEMPLATE = "/app/nuclei-templates/http-missing-security-headers.yaml"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_history(history):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


@app.route("/")
def home():
    history = load_history()
    return render_template("index.html", history=history)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        return redirect(url_for("home"))

    target = request.form.get("target", "").strip()

    if not target:
        history = load_history()
        return render_template(
            "index.html",
            history=history,
            error="Please enter a target URL."
        )

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output = os.path.join(RESULTS_DIR, f"output_{int(time.time())}.jsonl")

    cmd = [
        "nuclei",
        "-u", target,
        "-t", NUCLEI_TEMPLATE,
        "-jsonl",
        "-o", output,
        "-c", "1",
        "-rl", "1",
        "-timeout", "10",
        "-retries", "0",
        "-silent",
        "-duc"
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        stderr = r.stderr
    except Exception as e:
        history = load_history()
        return render_template(
            "index.html",
            history=history,
            target=target,
            findings=[],
            error=f"Scan error: {e}"
        )

    findings = []

    if os.path.exists(output):
        with open(output, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    history = load_history()

    history_item = {
        "target": target,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings_count": len(findings),
        "output_file": output
    }

    history.insert(0, history_item)
    history = history[:10]
    save_history(history)

    return render_template(
        "index.html",
        target=target,
        findings=findings,
        stderr=stderr,
        history=history
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
