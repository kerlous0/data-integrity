import pyotp
from flask import current_app
import base64
import os

def generate_totp_secret():
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()

def verify_totp(secret, token):
    """Verify a TOTP token against a secret key."""
    if not secret or not token:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def generate_qr_code(secret, email):
    """Generate a QR code for TOTP setup."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        email,
        issuer_name=current_app.config.get('TOTP_ISSUER', 'SecureDocs')
    )

def backup_codes_generate():
    """Generate backup codes for 2FA recovery."""
    codes = []
    for _ in range(8):  # Generate 8 backup codes
        code = base64.b32encode(os.urandom(10)).decode('utf-8')
        codes.append(code[:16])  # Take first 16 characters
    return codes 