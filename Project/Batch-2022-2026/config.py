import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:

    SECRET_KEY = "super_secure_key"

    SQLALCHEMY_DATABASE_URI = "sqlite:///data.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR,"uploads")

    LEDGER_FILE = os.path.join(BASE_DIR,"utils","ledger.json")