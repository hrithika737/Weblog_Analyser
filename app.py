import os
import re
import hashlib
import pandas as pd
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session, flash
from werkzeug.utils import secure_filename

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "logs.db")
ALLOWED_EXTENSIONS = {".log", ".txt"}

app = Flask(__name__, template_folder=BASE_DIR)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Regex for Apache/Nginx access logs.
log_pattern = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+'
    r'(?P<path>\S+)\s+HTTP/\d(?:\.\d)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)',
    re.IGNORECASE | re.MULTILINE
)

# ---------------------------
# Parsing & Saving to DB
# ---------------------------
def parse_log_file(file_path, source_file):
    records = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    content = (
        content.replace("â€œ", '"')
        .replace("â€", '"')
        .replace("â€\x9d", '"')
        .replace("“", '"')
        .replace("”", '"')
    )

    for match in log_pattern.finditer(content):
        try:
            ts = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            ts = None
        records.append({
            "ip": match.group("ip"),
            "timestamp": ts,
            "method": match.group("method").upper(),
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

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL UNIQUE,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            rows_imported INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def is_allowed_log_file(filename):
    return os.path.splitext(filename.lower())[1] in ALLOWED_EXTENSIONS

def get_file_hash(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def has_file_been_uploaded(file_hash):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT 1 FROM uploaded_files WHERE file_hash=?", (file_hash,)).fetchone()
    conn.close()
    return row is not None

def record_uploaded_file(filename, file_hash, rows_imported):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO uploaded_files (filename, file_hash, rows_imported) VALUES (?, ?, ?)",
        (filename, file_hash, rows_imported),
    )
    conn.commit()
    conn.close()

def process_uploaded_logs(file_paths):
    imported_files = 0
    imported_rows = 0
    skipped_duplicates = 0
    skipped_empty = 0

    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        file_hash = get_file_hash(file_path)

        if has_file_been_uploaded(file_hash):
            skipped_duplicates += 1
            continue

        df = parse_log_file(file_path, file_name)
        if not df.empty:
            save_to_db(df)
            record_uploaded_file(file_name, file_hash, len(df))
            imported_files += 1
            imported_rows += len(df)
        else:
            skipped_empty += 1

    return {
        "imported_files": imported_files,
        "imported_rows": imported_rows,
        "skipped_duplicates": skipped_duplicates,
        "skipped_empty": skipped_empty,
    }

# ---------------------------
# Suspicious IP Detection
# ---------------------------
def get_filtered_logs(date_from=None, date_to=None, ip_filter=None, url_filter=None):
    init_db()
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
    return df

def get_dashboard_charts(df):
    status_buckets = {
        "2xx Success": int(df[(df["status"] >= 200) & (df["status"] < 300)].shape[0]) if not df.empty else 0,
        "3xx Redirect": int(df[(df["status"] >= 300) & (df["status"] < 400)].shape[0]) if not df.empty else 0,
        "4xx Client Error": int(df[(df["status"] >= 400) & (df["status"] < 500)].shape[0]) if not df.empty else 0,
        "5xx Server Error": int(df[df["status"] >= 500].shape[0]) if not df.empty else 0,
    }

    if df.empty or "timestamp" not in df:
        request_timeline = {"labels": [], "values": []}
    else:
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce").dropna()
        hourly = timestamps.dt.strftime("%H:00").value_counts().sort_index()
        request_timeline = {
            "labels": hourly.index.tolist(),
            "values": [int(value) for value in hourly.values],
        }

    return {
        "status_labels": list(status_buckets.keys()),
        "status_values": list(status_buckets.values()),
        "timeline_labels": request_timeline["labels"],
        "timeline_values": request_timeline["values"],
    }

def get_suspicious_ips(date_from=None, date_to=None, ip_filter=None, url_filter=None):
    df = get_filtered_logs(date_from, date_to, ip_filter, url_filter)

    if df.empty:
        return [], 0, 0, 0, get_dashboard_charts(df)

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

    return suspicious_list, total_logs, total_errors, unique_ips, get_dashboard_charts(df)

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
        saved_files = []
        invalid_files = 0
        for file in files:
            if not file.filename:
                continue

            if not is_allowed_log_file(file.filename):
                invalid_files += 1
                continue

            filename = secure_filename(file.filename)
            if not filename:
                invalid_files += 1
                continue

            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)
            saved_files.append(file_path)

        summary = process_uploaded_logs(saved_files)

        if summary["imported_files"]:
            flash(
                f"Imported {summary['imported_rows']} log rows from {summary['imported_files']} file(s).",
                "success",
            )
        if summary["skipped_duplicates"]:
            flash(f"Skipped {summary['skipped_duplicates']} duplicate file(s).", "warning")
        if summary["skipped_empty"]:
            flash(f"Skipped {summary['skipped_empty']} file(s) with no supported log entries.", "warning")
        if invalid_files:
            flash(f"Rejected {invalid_files} unsupported file(s). Use .log or .txt files.", "danger")
        if not saved_files:
            flash("No valid log files were selected.", "danger")

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

    data, total_logs, total_errors, unique_ips, charts = get_suspicious_ips(date_from, date_to, ip_filter, url_filter)
    return render_template("results.html",
                           data=data,
                           total_logs=total_logs,
                           total_errors=total_errors,
                           unique_ips=unique_ips,
                           charts=charts,
                           filters={
                               "date_from": date_from or "",
                               "date_to": date_to or "",
                               "ip_filter": ip_filter or "",
                               "url_filter": url_filter or "",
                           })

@app.route("/get_urls/<ip>/<file>")
def get_urls(ip, file):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    if file != "null":
        rows = conn.execute("SELECT DISTINCT path FROM parsed_logs WHERE ip=? AND source_file=?", (ip, file)).fetchall()
    else:
        rows = conn.execute("SELECT DISTINCT path FROM parsed_logs WHERE ip=?", (ip,)).fetchall()
    conn.close()
    return jsonify([r[0] for r in rows if r[0]])

@app.route("/download_csv")
def download_csv():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM parsed_logs", conn)
    conn.close()
    out_path = "logs_export.csv"
    df.to_csv(out_path, index=False)
    return send_file(out_path, as_attachment=True)

@app.route("/download_pdf")
def download_pdf():
    if HTML is None:
        return "PDF export requires WeasyPrint. Install it with: pip install weasyprint", 503

    data, total_logs, total_errors, unique_ips, charts = get_suspicious_ips()
    html = render_template("pdf_templates.html",
                           data=data,
                           total_logs=total_logs,
                           total_errors=total_errors,
                           suspicious_count=len(data),
                           unique_ips=unique_ips,
                           charts=charts)
    pdf_path = "weekly_report.pdf"
    HTML(string=html).write_pdf(pdf_path)
    return send_file(pdf_path, as_attachment=True)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("landing"))

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
