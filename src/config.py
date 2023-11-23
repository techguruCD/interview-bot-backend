import os
import tempfile
from dotenv import load_dotenv

try:
    load_dotenv()
except:
    raise Exception("Could not load .env file")

TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEPLOYMENT_NAME = os.getenv("DEPLOYMENT_NAME")
ENDPOINT = os.getenv("ENDPOINT")
API_TYPE = os.getenv("API_TYPE")
API_VERSION = "2023-05-15"

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
APP_PORT = os.getenv("FLASK_APP_PORT")
JWT_SECRET_KEY = os.getenv("JWT_KEY")
CLIENT_ID_LINKEDIN = os.getenv("LINKEDIN_CLIENT_ID")
CLIENT_ID_GOOGLE = os.getenv("GOOGLE_CLIENT_ID")
LINKEDIN_TOKEN = os.getenv("LINKEDIN_TOKEN")
GOOGLE_TOKEN = os.getenv("GOOGLE_TOKEN")
GOOGLE_URL = os.getenv("GOOGLE_URL")
LINKEDIN_URL = os.getenv("LINKEDIN_URL")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

DATABASE_URL = (
    f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
