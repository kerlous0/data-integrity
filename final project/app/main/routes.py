from flask import render_template, flash, redirect, url_for, request, current_app, send_file
from flask_login import login_required, current_user
from app import db
from app.main import bp
from app.models import Document, AuditLog
from app.utils import encrypt_file, decrypt_file, sign_document, generate_keypair, verify_file_integrity, verify_signature, get_public_key
from werkzeug.utils import secure_filename
import os
import hashlib
import io
from datetime import datetime

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('main/index.html', title='Home', documents=documents)

@bp.route('/profile')
@login_required
def profile():
    return redirect(url_for('auth.profile'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Secure the filename and create unique filename
            original_filename = secure_filename(file.filename)
            filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{original_filename}"
            
            # Read file data
            file_data = file.read()
            
            # Calculate file hash before encryption
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Encrypt the file
            encrypted_data, encryption_iv = encrypt_file(file_data)
            
            # Generate key pair and sign the original file data
            private_key, _ = generate_keypair()
            signature = sign_document(private_key, file_data)
            
            # Ensure upload directory exists
            upload_dir = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_dir, exist_ok=True)
            
            # Save the encrypted file
            file_path = os.path.join(upload_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Create document record
            document = Document(
                filename=filename,
                original_filename=original_filename,
                file_hash=file_hash,
                signature=signature,
                encryption_iv=encryption_iv,
                user_id=current_user.id
            )
            
            db.session.add(document)
            
            # Create audit log entry
            log = AuditLog(
                user_id=current_user.id,
                action='upload_document',
                details=f'Uploaded document: {original_filename}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            
            db.session.commit()
            
            flash('File uploaded successfully')
            return redirect(url_for('main.index'))
        else:
            flash('File type not allowed')
            return redirect(request.url)
            
    return render_template('main/upload.html', title='Upload Document')

@bp.route('/download/<int:id>')
@login_required
def download_document(id):
    document = Document.query.get_or_404(id)
    
    # Check if user owns this document or is admin
    if document.user_id != current_user.id and not current_user.is_admin():
        # Log unauthorized access attempt
        log = AuditLog(
            user_id=current_user.id,
            action='download_attempt',
            details=f'Unauthorized attempt to download document: {document.original_filename}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Access denied')
        return redirect(url_for('main.index'))
    
    # Update last accessed timestamp
    document.last_accessed = datetime.utcnow()
    
    # Get file path
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], document.filename)
    
    # Check if file exists
    if not os.path.exists(file_path):
        flash('File not found')
        return redirect(url_for('main.index'))
    
    try:
        # Read and decrypt the file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, document.encryption_iv)
        
        # Verify file integrity using HMAC
        if not verify_file_integrity(decrypted_data, document.file_hash):
            # Log integrity failure
            log = AuditLog(
                user_id=current_user.id,
                action='integrity_check_failed',
                details=f'Integrity check failed for document: {document.original_filename}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            flash('File integrity check failed')
            return redirect(url_for('main.index'))
            
        # Verify digital signature
        public_key = get_public_key()  # You'll need to implement this to retrieve the public key
        if not verify_signature(public_key, document.signature, decrypted_data):
            # Log signature verification failure
            log = AuditLog(
                user_id=current_user.id,
                action='signature_verification_failed',
                details=f'Signature verification failed for document: {document.original_filename}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            flash('Digital signature verification failed')
            return redirect(url_for('main.index'))
        
        # Log successful download with integrity and signature verification
        log = AuditLog(
            user_id=current_user.id,
            action='download_document',
            details=f'Downloaded document: {document.original_filename} (integrity and signature verified)',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # Create BytesIO object for sending file
        file_data = io.BytesIO(decrypted_data)
        
        return send_file(
            file_data,
            download_name=document.original_filename,
            as_attachment=True
        )
        
    except Exception as e:
        # Log decryption/verification error
        log = AuditLog(
            user_id=current_user.id,
            action='download_error',
            details=f'Error processing document: {document.original_filename}, Error: {str(e)}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Error processing file')
        return redirect(url_for('main.index'))

@bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_document(id):
    document = Document.query.get_or_404(id)
    
    # Check if user owns this document or is admin
    if document.user_id != current_user.id and not current_user.is_admin():
        # Log unauthorized deletion attempt
        log = AuditLog(
            user_id=current_user.id,
            action='delete_attempt',
            details=f'Unauthorized attempt to delete document: {document.original_filename}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Access denied')
        return redirect(url_for('main.index'))
    
    # Delete the actual file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], document.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Log successful deletion
    log = AuditLog(
        user_id=current_user.id,
        action='delete_document',
        details=f'Deleted document: {document.original_filename}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    # Delete the database record
    db.session.delete(document)
    db.session.commit()
    
    # Redirect based on where the request came from
    if request.referrer and 'admin' in request.referrer:
        return redirect(url_for('admin.documents'))
    return redirect(url_for('main.index'))

@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate current password
    if not current_user.check_password(current_password):
        flash('Current password is incorrect')
        return redirect(url_for('auth.profile'))
    
    # Validate new password
    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('auth.profile'))
    
    # Update password
    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Password updated successfully')
    return redirect(url_for('auth.profile')) 