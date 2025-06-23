import os
import secrets
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID') or "your-google-client-id.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')  # Optional, for server-side flows
    
    # JWT Configuration
    JWT_SECRET = os.environ.get('JWT_SECRET') or secrets.token_hex(32)
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION = timedelta(hours=24)
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://accounts.google.com;"
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Less strict security for development
    SESSION_COOKIE_SECURE = False
    
    # Development-specific settings
    GOOGLE_OAUTH_REDIRECT_URI = "http://localhost:5000/auth/google"
    ALLOWED_ORIGINS = ["http://localhost:5000"]

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Strict security for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Production-specific settings
    GOOGLE_OAUTH_REDIRECT_URI = os.environ.get('GOOGLE_OAUTH_REDIRECT_URI')
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '').split(',')
    
    # Database URL for production (if using a database)
    DATABASE_URL = os.environ.get('DATABASE_URL')

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    
    # Test-specific settings
    WTF_CSRF_ENABLED = False
    GOOGLE_CLIENT_ID = "test-client-id"
    JWT_SECRET = "test-jwt-secret"

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])