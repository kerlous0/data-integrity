from flask import render_template, redirect, url_for, flash, request, session, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.urls import url_parse
from app import db
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm, TwoFactorForm, ChangePasswordForm
from app.models import User, AuditLog
from app.auth.mfa import generate_totp_secret, verify_totp
import pyotp
import qrcode
import io
import base64
from datetime import datetime

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            # Log failed login attempt
            log = AuditLog(
                user_id=user.id if user else None,
                action='login_failed',
                details=f'Failed login attempt for email: {form.email.data}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Invalid email or password')
            return redirect(url_for('auth.login'))
        
        # Store user ID for 2FA verification
        session['user_id'] = user.id
        
        # Check if 2FA is enabled
        if user.mfa_secret:
            # Log 2FA request
            log = AuditLog(
                user_id=user.id,
                action='2fa_requested',
                details='Two-factor authentication requested',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            return redirect(url_for('auth.two_factor'))
        
        # Update last login time
        user.last_login = datetime.utcnow()
        
        # Log successful login
        log = AuditLog(
            user_id=user.id,
            action='login_success',
            details='User logged in successfully',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    
    return render_template('auth/login.html', title='Sign In', form=form)

@bp.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        if verify_totp(user.mfa_secret, form.token.data):
            # Update last login time
            user.last_login = datetime.utcnow()
            
            # Log successful 2FA verification
            log = AuditLog(
                user_id=user.id,
                action='2fa_success',
                details='Two-factor authentication successful',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            login_user(user)
            session.pop('user_id', None)
            session.pop('oauth_login', None)  # Clear OAuth login flag
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)
            
        # Log failed 2FA attempt
        log = AuditLog(
            user_id=user.id,
            action='2fa_failed',
            details='Invalid two-factor authentication code',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Invalid authentication code')
    
    return render_template('auth/two_factor.html', form=form)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        # Generate and store TOTP secret
        secret = generate_totp_secret()
        user.mfa_secret = None  # Initially set to None until 2FA is set up
        
        db.session.add(user)
        
        # Log user registration
        log = AuditLog(
            user_id=None,  # User ID not available yet
            action='user_registered',
            details=f'New user registered: {user.email}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # Now we can create another log with the user ID
        log = AuditLog(
            user_id=user.id,
            action='user_registered',
            details='Account created successfully',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # Log in the user immediately after registration
        login_user(user)
        
        # Store the secret for 2FA setup
        session['mfa_secret'] = secret
        
        flash('Registration successful! Please set up 2FA.')
        return redirect(url_for('auth.setup_2fa'))
    
    return render_template('auth/register.html', title='Register', form=form)

@bp.route('/setup-2fa')
def setup_2fa():
    # For OAuth users, check if they have user_id in session but aren't logged in yet
    if not current_user.is_authenticated:
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('auth.login'))
        
        # Get user from session for OAuth flow
        user = User.query.get(session['user_id'])
        if not user:
            flash('Session expired. Please log in again.')
            return redirect(url_for('auth.login'))
        
        # If user already has 2FA set up, redirect to 2FA verification
        if user.mfa_secret:
            return redirect(url_for('auth.two_factor'))
    else:
        # For authenticated users, use current_user
        user = current_user
        
        # If user already has 2FA set up, redirect to index
        if user.mfa_secret:
            flash('Two-factor authentication is already set up.')
            return redirect(url_for('main.index'))
    
    if 'mfa_secret' not in session:
        secret = generate_totp_secret()
        session['mfa_secret'] = secret
        print(f"////////////////////MFA secret: {secret}")
    else:
        secret = session['mfa_secret']
        print(f"sddddddddddddddddddddddd/MFA secret: {secret}")

    
    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        user.email,
        issuer_name="SecureDocs"
    )
    
    # Create QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    # Create image and convert to base64
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_str = base64.b64encode(img_buffer.getvalue()).decode()
    
    return render_template('auth/setup_2fa.html',
                         secret=secret,
                         qr_code=img_str)

@bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'mfa_secret' not in session:
        flash('2FA setup error. Please try again.')
        return redirect(url_for('auth.setup_2fa'))
    
    token = request.form.get('token')
    if not token:
        flash('Please enter the verification code.')
        return redirect(url_for('auth.setup_2fa'))
    
    secret = session['mfa_secret']
    if verify_totp(secret, token):
        # Determine if user is authenticated or in OAuth flow
        if current_user.is_authenticated:
            # User is already authenticated (regular registration flow)
            user = current_user
        else:
            # OAuth flow - get user from session
            if 'user_id' not in session:
                flash('Session expired. Please log in again.')
                return redirect(url_for('auth.login'))
            
            user = User.query.get(session['user_id'])
            if not user:
                flash('Session expired. Please log in again.')
                return redirect(url_for('auth.login'))
        
        # Save the verified secret
        user.mfa_secret = secret
        
        # Log successful 2FA setup
        log = AuditLog(
            user_id=user.id,
            action='2fa_setup',
            details='Two-factor authentication enabled',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # Clean up session
        session.pop('mfa_secret', None)
        
        # If user was not authenticated (OAuth flow), log them in now
        if not current_user.is_authenticated:
            login_user(user)
            session.pop('user_id', None)
        
        # Clean up OAuth session flag
        if session.get('oauth_login'):
            session.pop('oauth_login', None)
        
        flash('Two-factor authentication has been enabled successfully!')
        return redirect(url_for('main.index'))
    
    # Determine user for logging
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = session.get('user_id')
    
    # Log failed 2FA setup attempt
    if user_id:
        log = AuditLog(
            user_id=user_id,
            action='2fa_setup_failed',
            details='Invalid verification code during 2FA setup',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    
    flash('Invalid verification code. Please try again.')
    return redirect(url_for('auth.setup_2fa'))

@bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        # Log the logout
        log = AuditLog(
            user_id=current_user.id,
            action='logout',
            details='User logged out',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/profile', methods=['GET'])
@login_required
def profile():
    password_form = ChangePasswordForm()
    return render_template('auth/profile.html', 
                         title='Profile',
                         password_form=password_form)

@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    password_form = ChangePasswordForm()
    if password_form.validate_on_submit():
        if not current_user.check_password(password_form.current_password.data):
            flash('Current password is incorrect.', 'error')
        else:
            current_user.set_password(password_form.new_password.data)
            
            # Log password change
            log = AuditLog(
                user_id=current_user.id,
                action='password_changed',
                details='Password was changed',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Your password has been updated.', 'success')
    else:
        for field, errors in password_form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')
    
    return redirect(url_for('auth.profile'))