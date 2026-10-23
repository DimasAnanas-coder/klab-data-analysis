import os
from dotenv import load_dotenv

from .path import ENV_FILE

load_dotenv(dotenv_path=ENV_FILE)

database_url = os.getenv("DATABASE_URL")
