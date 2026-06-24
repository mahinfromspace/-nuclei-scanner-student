from flask import Flask, request, render_template
import subprocess
import os
import time
import json
from datetime import datetime

app = Flask(__name__)

HISTORY_FILE = "results/history.json"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    with open(HISTORY_FILE, "r") as f:
        return json.load(f)


def save_history(history):
    os.makedirs("results", exist_ok=True)

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


@app.route("/")
def home():
    history = load_history()
    return render_template("index.html", history=history)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["target"]

    os.makedirs("results", exist_ok=True)
    output = f"results/output_{int(time.time())}.jsonl"

    cmd = [
        "nuclei",
        "-u", target,
        "-t", "/root/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
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
    except Exception as e:
        return f"Scan error: {e}"

    findings = []

    if os.path.exists(output):
        with open(output) as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))

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
        stderr=r.stderr,
        history=history
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
