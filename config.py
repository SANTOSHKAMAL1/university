# config.py
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    
    # Secret Key for Flask Sessions (CRITICAL for sessions to work)
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    # Session Configuration
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_TYPE = 'filesystem'  # Optional: store sessions on filesystem
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    UPLOAD_FOLDER = 'static/uploads'
    
    # Mail Configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.getenv('EMAIL_USER')
    MAIL_PASSWORD = os.getenv('EMAIL_PASS')
    MAIL_DEFAULT_SENDER = os.getenv('EMAIL_USER')
    
    # Flask Environment
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('DEBUG', 'True') == 'True'
    
    # Validate critical configs
    @staticmethod
    def validate():
        errors = []
        
        if not Config.MONGO_URI:
            errors.append("MONGO_URI is not set in .env file")
        
        if not Config.SECRET_KEY:
            errors.append("SECRET_KEY is not set in .env file")
        
        if not Config.MAIL_USERNAME:
            errors.append("EMAIL_USER is not set in .env file")
        
        if not Config.MAIL_PASSWORD:
            errors.append("EMAIL_PASS is not set in .env file")
        
        return errors