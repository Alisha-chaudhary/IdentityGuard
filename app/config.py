import os

# Override with an environment variable if needed. Default: a local SQLite file.
DATABASE_URL = os.getenv(
    "IDENTITYGUARD_DATABASE_URL",
    "sqlite:///./identityguard.db",
)

# Comma-separated list of origins allowed to call the API (e.g. your Vercel URL).
# Default keeps the original hardcoded Vercel origin as a fallback.
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "https://identity-guard-omega.vercel.app",
    ).split(",")
    if origin.strip()
]