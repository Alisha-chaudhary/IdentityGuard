# IdentityGuard
### Identity & Access Governance | IAM / PAM Security Lab

**IdentityGuard** is a Python-based identity and access governance application exploring how organizations manage digital identities, control access, govern permissions, and monitor privileged activities.

Built with **FastAPI, React, and SQLite**, the project brings together core Identity and Access Management (IAM) and Privileged Access Management (PAM) concepts in a hands-on security lab.

---

## ✦ Core Capabilities

| Capability | Description |
|:--|:--|
| **Identity Management** | Maintain user identities, roles, and access assignments. |
| **Role-Based Access Control** | Manage role permissions and enforce authorization checks. |
| **Identity Lifecycle (JML)** | Model Joiner, Mover, and Leaver workflows. |
| **Access Request Management** | Support access requests and approval workflows. |
| **Access Governance** | Implement access review workflows for reviewing assigned access. |
| **Privileged Access Management** | Model privileged access activities and related controls. |
| **Audit & Accountability** | Maintain records of security-relevant activities. |
| **Governance Reporting** | Generate reports for identity inventory, role assignments, requests, reviews, audit trails, and PAM activity. |
| **REST API & Authentication** | Expose application functionality through FastAPI with bearer-token authentication. |

## ✦ Technology Stack

| Layer | Technologies |
|:--|:--|
| **Backend** | Python, FastAPI |
| **Data Layer** | SQLAlchemy, SQLite, Pydantic |
| **Frontend** | React, JavaScript, Vite |
| **Authentication** | JWT, Argon2 password hashing |
| **Testing** | pytest, HTTPX |

## ✦ Project Structure

```text
IdentityGuard/
├── app/
│   ├── api/           # REST API endpoints
│   ├── auth/          # Authentication
│   ├── authz/         # Authorization and permissions
│   ├── core/          # Security utilities
│   ├── db/            # Database models, configuration, and seeding
│   ├── iam/           # Identity governance logic
│   ├── pam/           # Privileged access functionality
│   └── reports/       # Governance and activity reports
├── frontend/          # React + Vite interface
├── tests/             # Automated test suite
├── docs/              # Project documentation
├── requirements.txt
├── pytest.ini
└── README.md
```

## ✦ Getting Started

### Prerequisites

- Python 3.12 or a compatible supported Python version
- Node.js and npm compatible with the frontend dependencies
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Alisha-chaudhary/IdentityGuard.git
cd IdentityGuard
```

### 2. Set up the Python environment

Run the following commands in Windows PowerShell from the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure the database

IdentityGuard uses SQLite by default, with a database file named `identityguard.db` in the current working directory.

To configure the database URL explicitly:

```powershell
$env:IDENTITYGUARD_DATABASE_URL = "sqlite:///./identityguard.db"
```

> **Database safety:** Keep database files and backups out of version control. Do not run the seed script against an existing database unless you intend to perform its seeding operations.

### 4. Start the backend

From the project root, with the virtual environment activated:

```powershell
python -m uvicorn app.main:app --reload
```

The backend will be available at `http://127.0.0.1:8000`.

| Endpoint | Purpose |
|:--|:--|
| [`/health`](http://127.0.0.1:8000/health) | Application health check |
| [`/docs`](http://127.0.0.1:8000/docs) | Interactive API documentation |

### 5. Start the frontend

Open a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the local development URL printed by Vite. The configured development proxy forwards supported API paths to the backend.

### 6. Run the tests

From the project root:

```powershell
python -m pytest -q
```

### 7. Build the frontend

From the `frontend` directory:

```powershell
npm ci
npm run build
```

The production build is generated in `frontend/dist/`.

---

## ✦ Environment Configuration

| Variable | Purpose |
|:--|:--|
| `IDENTITYGUARD_DATABASE_URL` | SQLAlchemy database connection URL |
| `IDENTITYGUARD_JWT_SECRET` | Secret used to sign and verify JWT access tokens |
| `IDENTITYGUARD_SEED_PASSWORD` | Optional password for the development seed script |

Configure secrets through environment variables or an appropriate secret manager. **Never commit real credentials or secret values.**

For persistent environments, provide a stable JWT secret before starting the application. If the secret is omitted, the current implementation generates a random secret at process startup, which can invalidate previously issued tokens after a restart.

## ✦ Security Considerations

IdentityGuard is a learning and portfolio project designed to demonstrate IAM/PAM concepts and application security practices. It is not a certified enterprise IAM product or a production-ready privileged access management platform.

Before production use, further review would be needed for:

- Secret management and deployment configuration
- Database migrations, persistence, and backups
- Authentication and authorization controls
- Audit logging and monitoring
- Transport security and operational hardening

## ✦ Project Status

IdentityGuard is under active development. Features and implementation details should be evaluated against the current source code and tests.

Containerization and continuous integration should be considered available only after their configurations have been implemented and verified.

---

<p align="center">
  <strong>IdentityGuard</strong><br>
  <sub>Exploring identity security, access governance, and privileged access controls.</sub>
</p>
