from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"
VULNERABILITIES_PATH = PROJECT_ROOT / "data" / "vulnerabilities.json"
VERSIONS_PATH = PROJECT_ROOT / "data" / "versions.json"
