# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # ✅ Must be inside config.py

class Config:
    MONGO_URI = os.getenv('MONGO_URI')
from dotenv import load_dotenv
load_dotenv()
import os

EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
