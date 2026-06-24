from flask import Flask, request, render_template, send_from_directory
import subprocess, os, time, json, glob
from urllib.parse import urlparse

app = Flask(__name__)
RESULTS_DIR = "results"

def valid_target(url):
    p = urlparse(url)
    return p.scheme in ["http", "https"] and p.netloc

def read_jsonl(filename):
    path = os.path.join(RESULTS_DIR, os.path.basename(filename))
    findings = []

    if not os.path.exists(path):
        return findings

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    return findings

@app.route("/")
def home():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    history = []
    for path in sorted(glob.glob(os.path.join(RESULTS_DIR, "*.jsonl")), reverse=True):
        filename = os.path.basename(path)
        findings = read_jsonl(filename)
        history.append({
            "filename": filename,
            "count": len(findings)
        })

    return render_template("index.html", history=history)

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if not valid_target(target):
        return "Invalid target. Use http:// or https://", 400

    os.makedirs(RESULTS_DIR, exist_ok=True)

    filename = f"output_{int(time.time())}.jsonl"
    output_file = os.path.join(RESULTS_DIR, filename)

    cmd = [
        "nuclei",
        "-u", target,
        "-j",
        "-o", output_file,
        "-severity", "critical,high,medium",
        "-c", "3",
        "-rl", "3",
        "-bs", "5",
        "-silent",
        "-duc"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            return f"<h3>Scan failed</h3><pre>{result.stderr}</pre>", 500

    except subprocess.TimeoutExpired:
        return "Scan timed out after 5 minutes.", 504

    except FileNotFoundError:
        return "Nuclei is not installed in the container.", 500

    findings = read_jsonl(filename)

    return render_template(
        "index.html",
        target=target,
        filename=filename,
        findings=findings,
        history=[]
    )

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(
        RESULTS_DIR,
        os.path.basename(filename),
        as_attachment=True
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
