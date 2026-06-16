# SecureSight360

SecureSight360 is a professional cybersecurity assessment platform for authorized external website security posture reviews, explainable risk scoring, client-facing PDF reporting, and administrative oversight.

Current MVP assessment type: Basic External Website Security Posture Assessment.

This MVP is designed for safe, read-only external posture visibility. It is not a full penetration test and not a full vulnerability assessment.

## Current MVP Status

- Stable local MVP.
- FastAPI backend connected to React/Vite frontend.
- SQLite persistence enabled.
- Authenticated users can scan authorized domains.
- Admin dashboard, users, scans, and audit visibility implemented.
- PDF report generation implemented.
- Scanner, History, Reports, and View Details are connected to backend evidence.
- Assessment scope and limitations are visible in the UI and PDF report.

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic
- dnspython
- ReportLab
- Pytest

### Frontend

- React
- Vite
- TypeScript
- TanStack Router
- Lucide React icons
- Tailwind-style utility classes

## Local Paths

- Project root: C:\Users\allou\cybershield360
- Backend: C:\Users\allou\cybershield360\backend
- Frontend: C:\Users\allou\cybershield360\frontend
- Database: backend\data\cybershield360.db

Do not rename the database during the current MVP stage.

## Run Backend

Open PowerShell:

cd C:\Users\allou\cybershield360\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload

Backend URL: http://127.0.0.1:8000

## Run Frontend

Open a second PowerShell terminal:

cd C:\Users\allou\cybershield360\frontend
npm run dev

Frontend URL: http://localhost:8080

## Testing

Backend tests:

cd C:\Users\allou\cybershield360\backend
pytest

Frontend production build:

cd C:\Users\allou\cybershield360\frontend
npm run build

## Assessment Coverage

The Basic External Website Security Posture Assessment covers:

- Website availability.
- Final URL and HTTP status evidence.
- Response timing.
- HTTPS and TLS presence.
- Certificate validity, issuer, protocol, and expiry evidence.
- HTTP security headers including CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- DNS and email security signals including SPF, DMARC, MX, NS, TXT, CAA, and DKIM guidance where available.
- Basic technology evidence from safe response headers.
- Evidence-based risk scoring.
- Client-friendly findings and recommendations.
- Official PDF report generation from saved backend scan data.

## Assessment Limitations

The current MVP does not perform:

- Exploitation.
- Payload delivery.
- Credential attacks.
- Brute forcing.
- Destructive testing.
- Authenticated application testing.
- Deep crawling.
- Port scanning.
- Subdomain enumeration.
- Full penetration testing.
- Full vulnerability assessment.

Results represent externally observable evidence at scan time and should be validated during deeper security reviews when required.

## Ethical Authorization Notice

SecureSight360 must only be used on domains owned by the user or where the user has explicit written authorization to assess.

Unauthorized scanning may violate computer misuse, cybercrime, privacy, or data protection laws. The platform includes an authorization confirmation step and domain authorization checks to reduce misuse.

## Main Features

- User registration and login.
- Business email and domain-based account scoping.
- Domain authorization enforcement.
- Safe website scanner.
- Security score, risk level, and rating labels.
- Per-user scan history.
- Professional details view.
- Reports page with PDF download.
- Admin dashboard.
- Admin users page.
- Admin scans page.
- Audit visibility.

## Main API Endpoints

- GET /api/v1/health
- POST /api/v1/auth/login
- POST /api/v1/auth/register
- GET /api/v1/auth/me
- POST /api/v1/website/scan
- GET /api/v1/website/history/me
- GET /api/v1/website/history/me/{scan_id}
- GET /api/v1/website/reports/{scan_id}/pdf
- GET /api/v1/admin/dashboard
- GET /api/v1/admin/users
- GET /api/v1/admin/scans

## Roadmap

- Standard scan profile.
- Advanced scan profile.
- Phishing email detection.
- Email extension or add-on.
- 2FA and MFA.
- Power BI and analytics dashboards.
- Production deployment hardening.
- Production database migration.
- Logging, monitoring, backup, and restore workflows.

## Development Rules

- Keep the scanner evidence-based.
- Do not claim penetration testing capability for the current MVP.
- Do not claim full vulnerability assessment capability for the current MVP.
- Keep domain authorization checks active.
- Do not rename the database during the MVP phase.
- Run backend tests and frontend build before finalizing changes.
- Keep temporary patch, smoke-test, audit, and inspection files out of commits.
