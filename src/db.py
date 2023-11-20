from config import *
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database


try:
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    engine = create_engine(SQLALCHEMY_DATABASE_URL, future=True)
    if not database_exists(engine.url):
        print("Creating Database")
        create_database(engine.url)


except Exception as e:
    print(str(e))
