import os
from datetime import timedelta
import base64

class Config:
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    
    # Database configuration
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_NAME = os.environ.get('DB_NAME', 'securedocs')
    SQLALCHEMY_DATABASE_URI = f'mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Security settings
    SESSION_COOKIE_SECURE = True  # Only send cookies over HTTPS
    REMEMBER_COOKIE_SECURE = True  # Only send remember cookie over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
    REMEMBER_COOKIE_HTTPONLY = True  # Prevent JavaScript access to remember cookie
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:;",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block'
    }

    # OAuth 2.0 configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')

    # File upload configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'}

    # Encryption settings
    # Get the base64 encoded key from environment or generate a new 32-byte (256-bit) key
    raw_key = os.environ.get('ENCRYPTION_KEY')
    if raw_key:
        try:
            decoded_key = base64.b64decode(raw_key)
            # Ensure the key is exactly 32 bytes (256 bits)
            if len(decoded_key) != 32:
                ENCRYPTION_KEY = os.urandom(32)
            else:
                ENCRYPTION_KEY = decoded_key
        except:
            ENCRYPTION_KEY = os.urandom(32)
    else:
        ENCRYPTION_KEY = os.urandom(32)
    
    # Generate a separate 32-byte key for HMAC
    HMAC_KEY = os.urandom(32)

    # SSL configuration
    SSL_CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ssl', 'cert.pem')
    SSL_KEY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ssl', 'key.pem') 