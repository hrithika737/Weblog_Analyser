import os
import re
import pandas as pd
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session
from weasyprint import HTML

UPLOAD_FOLDER = "uploads"
DB_PATH = "logs.db"

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Needed for sessions
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ✅ Regex for Apache/Nginx logs
log_pattern = re.compile(
    r'(?P<ip>\S+)\s+- - \[(?P<timestamp>[^\]]+)\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>\S+)\s+HTTP/\d\.\d"\s+(?P<status>\d{3})\s+(?P<size>\d+)',
    re.IGNORECASE
)

# ---------------------------
# Parsing & Saving to DB
# ---------------------------
def parse_log_file(file_path, source_file):
    records = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                try:
                    ts = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
                except:
                    ts = None
                records.append({
                    "ip": match.group("ip"),
                    "timestamp": ts,
                    "method": match.group("method"),
                    "path": match.group("path"),
                    "status": int(match.group("status")),
                    "size": int(match.group("size")),
                    "source_file": source_file
                })
    return pd.DataFrame(records)

def save_to_db(df):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS parsed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TIMESTAMP,
            method TEXT,
            path TEXT,
            status INTEGER,
            size INTEGER,
            source_file TEXT
        )
    """)
    df.to_sql("parsed_logs", conn, if_exists="append", index=False)
    conn.commit()
    conn.close()

def process_uploaded_logs(upload_folder):
    for file_name in os.listdir(upload_folder):
        if file_name.lower().endswith((".log", ".txt")):
            file_path = os.path.join(upload_folder, file_name)
            df = parse_log_file(file_path, file_name)
            if not df.empty:
                save_to_db(df)

# ---------------------------
# Suspicious IP Detection
# ---------------------------
def get_suspicious_ips(date_from=None, date_to=None, ip_filter=None, url_filter=None):
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM parsed_logs WHERE 1=1"
    params = []

    if date_from:
        query += " AND date(timestamp) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(timestamp) <= ?"
        params.append(date_to)
    if ip_filter:
        query += " AND ip LIKE ?"
        params.append(f"%{ip_filter}%")
    if url_filter:
        query += " AND path LIKE ?"
        params.append(f"%{url_filter}%")

    df = pd.read_sql(query, conn, parse_dates=["timestamp"], params=params)
    conn.close()

    if df.empty:
        return [], 0, 0, 0

    suspicious_list = []
    for ip, group in df.groupby("ip"):
        error_count = group[group["status"] >= 400].shape[0]
        failed_logins = group[group["path"].str.contains("login", case=False, na=False)].shape[0]
        total_requests = len(group)
        risk_score = error_count * 2 + failed_logins
        risk_level = "LOW"
        if risk_score >= 10:
            risk_level = "HIGH"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
        suspicious_list.append({
            "ip": ip,
            "request_count": total_requests,
            "error_count": error_count,
            "failed_logins": failed_logins,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "last_seen": group["timestamp"].max(),
            "source_file": group["source_file"].iloc[0]
        })

    total_logs = len(df)
    total_errors = df[df["status"] >= 400].shape[0]
    unique_ips = df["ip"].nunique()

    return suspicious_list, total_logs, total_errors, unique_ips

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        if username and email and password:
            session["user"] = username
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="All fields are required.")
    return render_template("login.html")

@app.route("/upload", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        files = request.files.getlist("logfile")
        for file in files:
            if file.filename:
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
                file.save(file_path)
        process_uploaded_logs(UPLOAD_FOLDER)
        return redirect(url_for("results"))
    return render_template("index.html")

@app.route("/results")
def results():
    if "user" not in session:
        return redirect(url_for("login"))

    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    ip_filter = request.args.get("ip_filter")
    url_filter = request.args.get("url_filter")

    data, total_logs, total_errors, unique_ips = get_suspicious_ips(date_from, date_to, ip_filter, url_filter)
    return render_template("results.html",
                           data=data,
                           total_logs=total_logs,
                           total_errors=total_errors,
                           unique_ips=unique_ips)

@app.route("/get_urls/<ip>/<file>")
def get_urls(ip, file):
    conn = sqlite3.connect(DB_PATH)
    if file != "null":
        rows = conn.execute("SELECT DISTINCT path FROM parsed_logs WHERE ip=? AND source_file=?", (ip, file)).fetchall()
    else:
        rows = conn.execute("SELECT DISTINCT path FROM parsed_logs WHERE ip=?", (ip,)).fetchall()
    conn.close()
    return jsonify([r[0] for r in rows if r[0]])

@app.route("/download_csv")
def download_csv():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM parsed_logs", conn)
    conn.close()
    out_path = "logs_export.csv"
    df.to_csv(out_path, index=False)
    return send_file(out_path, as_attachment=True)

@app.route("/download_pdf")
def download_pdf():
    data, total_logs, total_errors, unique_ips = get_suspicious_ips()
    html = render_template("pdf_templates.html",
                           data=data,
                           total_logs=total_logs,
                           total_errors=total_errors,
                           unique_ips=unique_ips)
    pdf_path = "weekly_report.pdf"
    HTML(string=html).write_pdf(pdf_path)
    return send_file(pdf_path, as_attachment=True)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("landing"))

if __name__ == "__main__":
    app.run(debug=True)
