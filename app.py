from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from pathlib import Path
import sqlite3
import csv
import io
import re
import hashlib
import os
from datetime import datetime
import json
import math

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

app = Flask(__name__)
app.jinja_env.filters["fromjson"] = lambda value: json.loads(value or "{}")
app.secret_key = os.environ.get("DATASENTINEL_SECRET", "change-this-secret-key")
DATABASE = Path(__file__).with_name("datasentinel.db")
MAX_FILE_SIZE = 10 * 1024 * 1024


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        file_size INTEGER DEFAULT 0,
        file_hash TEXT,
        risk_score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'Low',
        confidence_score REAL DEFAULT 0,
        sensitive_count INTEGER DEFAULT 0,
        personal_count INTEGER DEFAULT 0,
        credential_count INTEGER DEFAULT 0,
        financial_count INTEGER DEFAULT 0,
        network_count INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        data_type TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        masked_value TEXT NOT NULL,
        location TEXT,
        recommendation TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        description TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)
    # Lightweight schema migration for existing installations.
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
    ml_columns = {
        "ml_anomaly_score": "REAL DEFAULT 0",
        "ml_risk_score": "INTEGER DEFAULT 0",
        "ml_risk_level": "TEXT DEFAULT 'Low'",
        "ml_indicator": "TEXT DEFAULT 'Normal'",
        "ml_confidence": "REAL DEFAULT 0",
        "combined_risk_score": "INTEGER DEFAULT 0",
        "combined_risk_level": "TEXT DEFAULT 'Low'",
        "ml_model_version": "TEXT DEFAULT 'IsolationForest-v1'",
        "feature_json": "TEXT DEFAULT '{}'"
    }
    for column, definition in ml_columns.items():
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at)")
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def audit(user_id, action, description=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (user_id, action, description) VALUES (?, ?, ?)",
        (user_id, action, description),
    )
    conn.commit()
    conn.close()


def mask_value(value):
    value = str(value)
    if len(value) <= 6:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


RULES = [
    {
        "name": "Email Address",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "category": "Personal", "severity": "Medium", "confidence": 0.98,
        "recommendation": "Mask personal email addresses when sharing data externally."
    },
    {
        "name": "Phone Number",
        "pattern": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
        "category": "Personal", "severity": "Medium", "confidence": 0.92,
        "recommendation": "Mask phone numbers and avoid unnecessary public exposure."
    },
    {
        "name": "Indian PAN Number",
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "category": "Financial", "severity": "High", "confidence": 0.97,
        "recommendation": "Protect PAN identifiers and remove them from public documents."
    },
    {
        "name": "Credit Card Number",
        "pattern": r"\b(?:\d[ -]*?){13,19}\b",
        "category": "Financial", "severity": "Critical", "confidence": 0.80,
        "recommendation": "Remove payment-card data or tokenize it before storage/sharing."
    },
    {
        "name": "IPv4 Address",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "category": "Network", "severity": "Medium", "confidence": 0.96,
        "recommendation": "Review whether internal IP addresses should be exposed."
    },
    {
        "name": "MAC Address",
        "pattern": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        "category": "Network", "severity": "Low", "confidence": 0.98,
        "recommendation": "Avoid exposing device identifiers unless operationally necessary."
    },
    {
        "name": "AWS Access Key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "category": "Credential", "severity": "Critical", "confidence": 0.99,
        "recommendation": "Revoke and rotate the AWS key immediately."
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        "category": "Credential", "severity": "Critical", "confidence": 0.97,
        "recommendation": "Revoke exposed API keys and store secrets in a secure vault."
    },
    {
        "name": "JWT Token",
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "category": "Credential", "severity": "Critical", "confidence": 0.98,
        "recommendation": "Invalidate exposed JWTs and issue new tokens."
    },
    {
        "name": "Password Credential",
        "pattern": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}",
        "category": "Credential", "severity": "Critical", "confidence": 0.95,
        "recommendation": "Remove the credential and rotate the affected password."
    },
    {
        "name": "Secret Credential",
        "pattern": r"(?i)\b(?:secret|client_secret|private_key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{12,}",
        "category": "Credential", "severity": "Critical", "confidence": 0.94,
        "recommendation": "Move secrets into a secrets-management solution."
    },
    {
        "name": "Credential in URL",
        "pattern": r"(?i)\bhttps?://[^/\s:@]+:[^@\s]+@[^/\s]+",
        "category": "Credential", "severity": "Critical", "confidence": 0.98,
        "recommendation": "Remove credentials from URLs and rotate them."
    },
    {
        "name": "IBAN",
        "pattern": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
        "category": "Financial", "severity": "High", "confidence": 0.88,
        "recommendation": "Protect bank-account identifiers from unnecessary exposure."
    },
]

SEVERITY_POINTS = {"Critical": 30, "High": 20, "Medium": 10, "Low": 4}


def detect_sensitive_data(text):
    detections = []
    for rule in RULES:
        try:
            matches = re.finditer(rule["pattern"], text)
        except re.error:
            continue
        for match in matches:
            value = match.group(0)
            line = text[:match.start()].count("\n") + 1
            detections.append({
                "data_type": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "masked_value": mask_value(value),
                "location": f"Line {line}",
                "recommendation": rule["recommendation"],
            })
    return detections


def risk_result(detections):
    if not detections:
        return {"score": 0, "level": "Low"}
    raw = sum(SEVERITY_POINTS.get(d["severity"], 0) * d["confidence"] for d in detections)
    score = min(100, round(raw))
    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"
    return {"score": score, "level": level}


def counts(detections):
    categories = {"Personal": 0, "Credential": 0, "Financial": 0, "Network": 0}
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for d in detections:
        categories[d["category"]] = categories.get(d["category"], 0) + 1
        severities[d["severity"]] = severities.get(d["severity"], 0) + 1
    return categories, severities


def average_confidence(detections):
    if not detections:
        return 0
    return round(sum(d["confidence"] for d in detections) / len(detections) * 100, 2)



ML_MODEL_VERSION = "IsolationForest-v1"
FEATURE_NAMES = [
    "text_length", "line_count", "word_count", "unique_word_ratio",
    "entropy", "finding_density", "critical_ratio", "high_ratio",
    "medium_ratio", "low_ratio", "credential_ratio", "financial_ratio",
    "personal_ratio", "network_ratio", "max_severity_points",
    "avg_detection_confidence"
]


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def extract_features(text, detections):
    text_length = len(text)
    words = re.findall(r"\b\w+\b", text.lower())
    word_count = len(words)
    unique_word_ratio = (len(set(words)) / word_count) if word_count else 0
    total = max(len(detections), 1)
    critical = sum(d["severity"] == "Critical" for d in detections)
    high = sum(d["severity"] == "High" for d in detections)
    medium = sum(d["severity"] == "Medium" for d in detections)
    low = sum(d["severity"] == "Low" for d in detections)
    credential = sum(d["category"] == "Credential" for d in detections)
    financial = sum(d["category"] == "Financial" for d in detections)
    personal = sum(d["category"] == "Personal" for d in detections)
    network = sum(d["category"] == "Network" for d in detections)
    return {
        "text_length": text_length,
        "line_count": max(text.count("\n") + 1, 1),
        "word_count": word_count,
        "unique_word_ratio": round(unique_word_ratio, 6),
        "entropy": round(shannon_entropy(text), 6),
        "finding_density": round(len(detections) / max(text_length, 1) * 1000, 6),
        "critical_ratio": round(critical / total, 6),
        "high_ratio": round(high / total, 6),
        "medium_ratio": round(medium / total, 6),
        "low_ratio": round(low / total, 6),
        "credential_ratio": round(credential / total, 6),
        "financial_ratio": round(financial / total, 6),
        "personal_ratio": round(personal / total, 6),
        "network_ratio": round(network / total, 6),
        "max_severity_points": max((SEVERITY_POINTS.get(d["severity"], 0) for d in detections), default=0),
        "avg_detection_confidence": round(
            sum(d["confidence"] for d in detections) / len(detections), 6
        ) if detections else 0.0,
    }


def _feature_vector(features):
    return [float(features.get(name, 0)) for name in FEATURE_NAMES]


def _bootstrap_profiles():
    # Benign reference profiles make the first few scans usable before enough
    # real historical scans exist. They are not persisted as user data.
    return [
        [800, 35, 140, .42, 4.0, .05, 0, .02, .35, .63, .01, .03, .45, .51, 20, .82],
        [1500, 70, 260, .38, 4.4, .08, .02, .04, .44, .50, .03, .04, .48, .45, 20, .84],
        [3000, 120, 520, .34, 4.7, .10, .03, .06, .48, .43, .04, .05, .46, .45, 20, .86],
        [600, 25, 100, .46, 3.8, .03, 0, .01, .30, .69, 0, .02, .55, .43, 10, .80],
        [5000, 200, 900, .31, 4.9, .12, .04, .08, .48, .40, .05, .07, .42, .46, 20, .87],
        [2200, 90, 400, .36, 4.6, .07, .01, .05, .40, .54, .02, .03, .50, .45, 10, .83],
        [10000, 400, 1800, .28, 5.1, .15, .03, .07, .50, .40, .04, .06, .44, .46, 20, .88],
        [1000, 45, 180, .40, 4.2, .06, .01, .03, .38, .58, .02, .03, .49, .46, 10, .82],
    ]


def ml_anomaly_analysis(text, detections, current_features, historical_rows):
    vector = _feature_vector(current_features)
    history = []
    for row in historical_rows:
        try:
            history.append(_feature_vector(json.loads(row["feature_json"])))
        except Exception:
            continue

    training = _bootstrap_profiles() + history
    # The current scan is scored against the reference population, not included
    # in the training set, so its anomaly score is independent of itself.
    if IsolationForest is None or len(training) < 5:
        return {
            "anomaly_score": 0, "risk_score": 0, "level": "Low",
            "indicator": "ML unavailable", "confidence": 0,
            "model_version": "ML-unavailable", "features": current_features
        }

    model = IsolationForest(
        n_estimators=150, contamination="auto", random_state=42
    )
    model.fit(training)
    decision = float(model.decision_function([vector])[0])
    # Convert IsolationForest's normality score to a stable 0-100 anomaly risk.
    anomaly = max(0.0, min(100.0, 50.0 - (decision * 250.0)))
    anomaly = round(anomaly, 2)

    if anomaly >= 75:
        level = "Critical"
        indicator = "Highly anomalous"
    elif anomaly >= 50:
        level = "High"
        indicator = "Anomalous"
    elif anomaly >= 25:
        level = "Medium"
        indicator = "Elevated anomaly"
    else:
        level = "Low"
        indicator = "Normal pattern"

    confidence = round(min(99.0, 55.0 + min(len(training), 50) * 0.75), 2)
    return {
        "anomaly_score": anomaly,
        "risk_score": round(anomaly),
        "level": level,
        "indicator": indicator,
        "confidence": confidence,
        "model_version": ML_MODEL_VERSION,
        "features": current_features
    }


def combined_risk_result(rule_risk, ml_result):
    # Rule detection remains the primary signal; ML adds anomaly context.
    combined = round((rule_risk["score"] * 0.65) + (ml_result["risk_score"] * 0.35))
    if combined >= 75:
        level = "Critical"
    elif combined >= 50:
        level = "High"
    elif combined >= 25:
        level = "Medium"
    else:
        level = "Low"
    return {"score": min(100, combined), "level": level}

def extract_file_text(filename, data):
    ext = Path(filename).suffix.lower()
    if ext == ".pdf":
        if PdfReader is None:
            raise ValueError("pypdf is not installed. Run: pip install -r requirements.txt")
        reader = PdfReader(io.BytesIO(data))
        pages = [(page.extract_text() or "") for page in reader.pages]
        return "\n".join(pages), "PDF"

    allowed_text = {
        ".txt": "TXT", ".csv": "CSV", ".log": "LOG", ".json": "JSON",
        ".xml": "XML", ".html": "HTML", ".py": "PY", ".js": "JS",
        ".java": "JAVA", ".php": "PHP", ".sql": "SQL"
    }
    if ext in allowed_text:
        return data.decode("utf-8", errors="ignore"), allowed_text[ext]
    raise ValueError("Unsupported file type. Use PDF, CSV, TXT, LOG, JSON, XML, HTML, PY, JS, JAVA, PHP or SQL.")


def save_scan(user_id, filename, scan_type, data, detections):
    text = data.decode("utf-8", errors="ignore")
    rule_risk = risk_result(detections)
    category_counts, severity_counts = counts(detections)
    features = extract_features(text, detections)

    conn = get_db()
    historical_rows = conn.execute("""
        SELECT feature_json FROM scans
        WHERE user_id = ? AND feature_json IS NOT NULL
        ORDER BY id DESC LIMIT 100
    """, (user_id,)).fetchall()

    ml = ml_anomaly_analysis(text, detections, features, historical_rows)
    combined = combined_risk_result(rule_risk, ml)

    cur = conn.execute("""
        INSERT INTO scans (
            user_id, filename, scan_type, file_size, file_hash,
            risk_score, risk_level, confidence_score, sensitive_count,
            personal_count, credential_count, financial_count, network_count,
            critical_count, high_count, medium_count, low_count,
            ml_anomaly_score, ml_risk_score, ml_risk_level, ml_indicator,
            ml_confidence, combined_risk_score, combined_risk_level,
            ml_model_version, feature_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, filename, scan_type, len(data), sha256_bytes(data),
        combined["score"], combined["level"], average_confidence(detections),
        len(detections), category_counts["Personal"], category_counts["Credential"],
        category_counts["Financial"], category_counts["Network"],
        severity_counts["Critical"], severity_counts["High"],
        severity_counts["Medium"], severity_counts["Low"],
        ml["anomaly_score"], ml["risk_score"], ml["level"], ml["indicator"],
        ml["confidence"], combined["score"], combined["level"],
        ml["model_version"], json.dumps(features)
    ))
    scan_id = cur.lastrowid

    for d in detections:
        conn.execute("""
            INSERT INTO detections (
                scan_id, data_type, category, severity, confidence,
                masked_value, location, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, d["data_type"], d["category"], d["severity"],
            d["confidence"], d["masked_value"], d["location"], d["recommendation"]
        ))
    conn.commit()
    conn.close()
    return scan_id, combined


@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            return render_template("register.html", error="Please fill in all fields.")
        if len(password) < 6:
            return render_template("register.html", error="Password must contain at least 6 characters.")

        conn = get_db()
        exists = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if exists:
            conn.close()
            return render_template("register.html", error="This email is already registered.")

        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, generate_password_hash(password))
        )
        conn.commit()
        conn.close()
        return redirect(url_for("login", registered=1))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            audit(user["id"], "LOGIN", "Successful login")
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid email or password.")

    return render_template("login.html", registered=request.args.get("registered") == "1")


@app.route("/logout")
@login_required
def logout():
    audit(session["user_id"], "LOGOUT", "User logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    conn = get_db()

    stats = conn.execute("""
        SELECT
            COUNT(*) AS total_scans,
            COALESCE(SUM(sensitive_count), 0) AS total_sensitive,
            COALESCE(SUM(critical_count), 0) AS critical,
            COALESCE(SUM(high_count), 0) AS high,
            COALESCE(AVG(risk_score), 0) AS avg_risk,
            COALESCE(SUM(personal_count), 0) AS personal,
            COALESCE(SUM(credential_count), 0) AS credentials,
            COALESCE(SUM(financial_count), 0) AS financial,
            COALESCE(SUM(network_count), 0) AS network
        FROM scans WHERE user_id = ?
    """, (uid,)).fetchone()

    recent = conn.execute("""
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 8
    """, (uid,)).fetchall()

    risk_rows = conn.execute("""
        SELECT risk_level, COUNT(*) AS total
        FROM scans WHERE user_id = ?
        GROUP BY risk_level
    """, (uid,)).fetchall()

    conn.close()

    risk_chart = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for row in risk_rows:
        risk_chart[row["risk_level"]] = row["total"]

    return render_template(
        "dashboard.html",
        stats=stats,
        recent=recent,
        risk_chart=risk_chart
    )


@app.route("/scan")
@login_required
def scan_page():
    return render_template("scan.html")


@app.route("/scan/text", methods=["POST"])
@login_required
def scan_text():
    text = request.form.get("text", "")
    if not text.strip():
        return render_template("scan.html", error="Enter some text before scanning.", active_tab="text")

    data = text.encode("utf-8")
    scan_id, _ = save_scan(session["user_id"], "Text Input", "TEXT", data, detect_sensitive_data(text))
    audit(session["user_id"], "TEXT_SCAN", f"Text scan #{scan_id}")
    return redirect(url_for("scan_details", scan_id=scan_id))


@app.route("/scan/file", methods=["POST"])
@login_required
def scan_file():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return render_template("scan.html", error="Choose a file first.", active_tab="file")

    data = uploaded.read()
    if len(data) > MAX_FILE_SIZE:
        return render_template("scan.html", error="File is larger than 10 MB.", active_tab="file")

    try:
        text, scan_type = extract_file_text(uploaded.filename, data)
    except ValueError as exc:
        return render_template("scan.html", error=str(exc), active_tab="file")
    except Exception as exc:
        return render_template("scan.html", error=f"Could not read the file: {exc}", active_tab="file")

    conn = get_db()
    old = conn.execute("""
        SELECT id FROM scans
        WHERE user_id = ? AND file_hash = ?
        ORDER BY id DESC LIMIT 1
    """, (session["user_id"], sha256_bytes(data))).fetchone()
    conn.close()

    if old:
        return redirect(url_for("scan_details", scan_id=old["id"]))

    detections = detect_sensitive_data(text)
    scan_id, _ = save_scan(session["user_id"], uploaded.filename, scan_type, data, detections)
    audit(session["user_id"], "FILE_SCAN", f"{uploaded.filename} -> scan #{scan_id}")
    return redirect(url_for("scan_details", scan_id=scan_id))


@app.route("/scan/<int:scan_id>")
@login_required
def scan_details(scan_id):
    conn = get_db()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"])
    ).fetchone()

    if not scan:
        conn.close()
        return "Scan not found.", 404

    detections = conn.execute(
        "SELECT * FROM detections WHERE scan_id = ? ORDER BY severity, id",
        (scan_id,)
    ).fetchall()
    conn.close()

    return render_template("scan_details.html", scan=scan, detections=detections)


@app.route("/history")
@login_required
def history():
    search = request.args.get("search", "").strip()
    risk = request.args.get("risk", "").strip()
    conn = get_db()

    query = "SELECT * FROM scans WHERE user_id = ?"
    params = [session["user_id"]]

    if search:
        query += " AND (filename LIKE ? OR scan_type LIKE ?)"
        value = f"%{search}%"
        params += [value, value]

    if risk:
        query += " AND risk_level = ?"
        params.append(risk)

    query += " ORDER BY datetime(created_at) DESC, id DESC"
    scans = conn.execute(query, params).fetchall()
    conn.close()

    return render_template("history.html", scans=scans, search=search, risk=risk)


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    conn = get_db()
    scan = conn.execute(
        "SELECT filename FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"])
    ).fetchone()

    if scan:
        conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, session["user_id"]))
        conn.commit()
    conn.close()

    audit(session["user_id"], "DELETE_SCAN", f"Deleted scan #{scan_id}")
    return redirect(url_for("history"))


@app.route("/history/export")
@login_required
def export_history():
    conn = get_db()
    rows = conn.execute("""
        SELECT filename, scan_type, risk_score, risk_level,
               confidence_score, sensitive_count, personal_count,
               credential_count, financial_count, network_count,
               critical_count, high_count, medium_count, low_count,
               ml_anomaly_score, ml_risk_score, ml_risk_level, ml_indicator,
               ml_confidence, combined_risk_score, combined_risk_level,
               ml_model_version, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY datetime(created_at) DESC
    """, (session["user_id"],)).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Filename", "Scan Type", "Risk Score", "Risk Level",
        "Confidence %", "Sensitive Records", "Personal",
        "Credentials", "Financial", "Network",
        "Critical", "High", "Medium", "Low",
        "ML Anomaly Score", "ML Risk Score", "ML Risk Level", "ML Indicator",
        "ML Confidence %", "Combined Risk Score", "Combined Risk Level",
        "ML Model Version", "Created At"
    ])

    for row in rows:
        writer.writerow(list(row))

    audit(session["user_id"], "EXPORT_HISTORY", "Exported scan history to CSV")
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="datasentinel_scan_history.csv"
    )


@app.route("/api/analytics")
@login_required
def analytics():
    conn = get_db()
    uid = session["user_id"]
    rows = conn.execute("""
        SELECT
            COALESCE(SUM(personal_count),0) personal,
            COALESCE(SUM(credential_count),0) credentials,
            COALESCE(SUM(financial_count),0) financial,
            COALESCE(SUM(network_count),0) network
        FROM scans WHERE user_id = ?
    """, (uid,)).fetchone()
    conn.close()

    return jsonify({
        "categories": {
            "Personal": rows["personal"],
            "Credential": rows["credentials"],
            "Financial": rows["financial"],
            "Network": rows["network"]
        }
    })


@app.route("/health")
def health():
    return jsonify({"application": "DataSentinel AI", "status": "online"})


if __name__ == "__main__":
    init_database()
    app.run(debug=True)
