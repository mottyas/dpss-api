import os
from pathlib import Path

app_title = "dpss-api"
api_version = "1.0.0"

# db_conn_string = "sqlite:///migrator/todo-api.sqlite"
DEFAULT_CONN_STRING = 'postgresql+psycopg2://postgres:postgres@localhost:5432/dpss_service_db'
SERVICE_DB_CONNECTION_STRING = os.getenv('DATABASE_URL', DEFAULT_CONN_STRING)

DEFAULT_SERVICE_DB_PATH = '/home/motya/malife/projects/depss-api/databases/service.db'
SERVICE_DB_PATH = Path(os.getenv('SERVICE_DB_PATH', DEFAULT_SERVICE_DB_PATH))

DEFAULT_DATA_DIR = '/home/motya/malife/projects/depss/data'
DATA_DIR = Path(os.getenv('DATA_DIR', DEFAULT_DATA_DIR))

DEFAULT_VULNER_DB_PATH = '/home/motya/malife/projects/depss/vulnerabilities/vulner.db'
VULNER_DB_PATH = Path(os.getenv('VULNER_DB_PATH', DEFAULT_VULNER_DB_PATH))

DEFAULT_VULNER_PACKAGES_DIR_PATH = '/home/motya/malife/projects/depss/vulnerabilities/packages/pyup-1.20250224.001/content'
VULNER_PACKAGES_DIR_PATH = Path(os.getenv('VULNER_PACKAGES_DIR_PATH', DEFAULT_VULNER_PACKAGES_DIR_PATH))
