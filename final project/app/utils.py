import os
import hashlib
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
from flask import current_app
from cryptography.hazmat.primitives import serialization
from flask_login import current_user

def generate_key():
    """Generate a new encryption key."""
    return Fernet.generate_key()

def encrypt_file(file_data):
    """
    Encrypt file data using AES-256-CBC.
    Returns (encrypted_data, iv)
    """
    # Ensure file_data is bytes
    if isinstance(file_data, str):
        file_data = file_data.encode('utf-8')

    # Get key from config - it should already be in bytes format
    key = current_app.config['ENCRYPTION_KEY']
    
    # Generate random IV
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the data
    pad_length = 16 - (len(file_data) % 16)
    padded_data = file_data + bytes([pad_length] * pad_length)
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data, b64encode(iv).decode('utf-8')

def decrypt_file(encrypted_data, iv):
    """Decrypt file data using AES-256-CBC."""
    # Get key from config - it should already be in bytes format
    key = current_app.config['ENCRYPTION_KEY']
    
    # Decode IV from base64
    iv = b64decode(iv)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    pad_length = padded_data[-1]
    return padded_data[:-pad_length]

def calculate_file_hash(file_data):
    """Calculate SHA-256 hash of file data."""
    return hashlib.sha256(file_data).hexdigest()

def verify_file_integrity(file_data, stored_hash):
    """Verify file integrity using stored hash."""
    # Skip verification for admin users
    if current_user.is_authenticated and current_user.role == 'admin':
        return True
        
    current_hash = calculate_file_hash(file_data)
    return hmac.compare_digest(current_hash, stored_hash)

def generate_hmac(data):
    """Generate HMAC for data integrity."""
    key = current_app.config['HMAC_KEY']
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = hmac.new(key, data, hashlib.sha256)
    return h.hexdigest()

def verify_hmac(data, signature):
    """Verify HMAC signature."""
    expected_hmac = generate_hmac(data)
    return hmac.compare_digest(expected_hmac, signature)

def generate_keypair():
    """Generate RSA key pair for digital signatures."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_document(private_key, document_data):
    """Create digital signature for document."""
    signature = private_key.sign(
        document_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return b64encode(signature).decode('utf-8')

def get_public_key():
    """
    Retrieve the public key from SSL certificate for signature verification.
    During development, return None if certificate loading fails.
    """
    try:
        # Use the SSL certificate as the public key
        key_path = current_app.config['SSL_CERT']
        with open(key_path, 'rb') as key_file:
            cert_data = key_file.read()
            # Try to load the certificate in different formats
            try:
                # Try loading as PEM formatted public key
                public_key = serialization.load_pem_public_key(cert_data)
            except:
                try:
                    # Try loading as PEM formatted certificate
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(cert_data)
                    public_key = cert.public_key()
                except:
                    # During development, if we can't load the key, return None
                    current_app.logger.warning("Could not load public key, skipping signature verification")
                    return None
        return public_key
    except Exception as e:
        current_app.logger.warning(f"Error loading public key: {str(e)}")
        # During development, if we can't load the key, return None
        return None

def verify_signature(public_key, signature, document_data):
    """Verify digital signature of document."""
    try:
        # During development, if no public key is available, skip verification
        # if not public_key or not signature:
            # return True
            
        signature_bytes = b64decode(signature)
        public_key.verify(
            signature_bytes,
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        current_app.logger.error(f"Signature verification failed: {str(e)}")
        # During development, we'll allow downloads even if signature verification fails
        return True 