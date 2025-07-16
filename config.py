# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # ✅ Must be inside config.py

class Config:
    MONGO_URI = os.getenv('MONGO_URI')
