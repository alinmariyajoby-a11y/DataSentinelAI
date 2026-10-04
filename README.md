# DataSentinel AI

Complete Flask + SQLite sensitive-data exposure analysis project.

## Setup on Windows PowerShell

```powershell
cd C:\Users\alinm\OneDrive\Desktop\DataSentinelAI
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, you can run without activation:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe app.py
```

Open:

http://127.0.0.1:5000

The application creates `datasentinel.db` automatically. Your older `database.db` is not used by this version.

## Included

- Registration/login/logout
- SQLite user-specific records
- Text scanning
- CSV/PDF/document scanning
- Sensitive-data detection
- API key, AWS key, JWT, password and secret detection
- Personal / Credential / Financial / Network classification
- Critical/High/Medium/Low severity
- Confidence score
- Risk score and risk level
- Masked values
- Security recommendations
- Dashboard analytics
- Scan history
- Search/filter
- Delete scan
- CSV history export
- File hashing and duplicate detection
- Audit logging
- ML-based anomaly detection using Isolation Forest
- ML risk indicator and anomaly score for every scan
- Rule-based + ML combined risk score (65% rules + 35% ML)
- 16-feature extraction from every scan
- ML results and extracted features stored with each scan
- ML risk details displayed in scan reports and history
- Responsive dark cybersecurity UI

For real deployments, replace the Flask secret key with an environment variable and add CSRF protection, secure cookies, rate limiting and production WSGI hosting.

## ML security layer

Each scan now extracts 16 numerical features, including text length, entropy,
finding density, severity ratios, credential ratio and detection confidence.
An Isolation Forest model compares the scan with benign reference profiles and
the user's historical scan patterns. The ML anomaly score is combined with the
existing deterministic rule risk to produce the final risk score.

The application stores the ML anomaly score, ML risk level, ML indicator,
ML confidence, model version, combined risk and feature JSON in the `scans`
table. Existing databases are migrated automatically when the application starts.
