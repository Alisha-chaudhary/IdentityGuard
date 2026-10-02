import os

# Override with an environment variable if needed. Default: a local SQLite file.
DATABASE_URL = os.getenv(
    "IDENTITYGUARD_DATABASE_URL",
    "sqlite:///./identityguard.db",
)