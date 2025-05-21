from flask import current_app, url_for, session, redirect, request, flash
from authlib.integrations.flask_client import OAuth
from app.auth import bp
from app import db
from app.models import User
from app.auth.mfa import generate_totp_secret
from flask_login import login_user
import secrets

oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    
    # Google OAuth setup
    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        client_kwargs={
            'scope': 'openid email profile',
            'prompt': 'select_account',
            'nonce': lambda: secrets.token_urlsafe(16)
        }
    )

    # GitHub OAuth setup
    oauth.register(
        name='github',
        client_id=app.config['GITHUB_CLIENT_ID'],
        client_secret=app.config['GITHUB_CLIENT_SECRET'],
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )

@bp.route('/login/google')
def google_login():
    # Generate and store nonce
    nonce = secrets.token_urlsafe(16)
    session['google_auth_nonce'] = nonce
    
    redirect_uri = url_for('auth.google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@bp.route('/login/github')
def github_login():
    redirect_uri = url_for('auth.github_authorize', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@bp.route('/authorize/google')
def google_authorize():
    try:
        token = oauth.google.authorize_access_token()
        nonce = session.pop('google_auth_nonce', None)
        if not nonce:
            flash('Authentication failed: Invalid session')
            return redirect(url_for('auth.login'))
            
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        email = user_info.get('email')
        
        if not email:
            flash('Could not get email from Google')
            return redirect(url_for('auth.login'))
        
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create new user
            username = user_info.get('name', email.split('@')[0])
            user = User(username=username, email=email)
            user.set_password(secrets.token_urlsafe(32))  # Set a random secure password
            db.session.add(user)
            db.session.commit()
            
            # Store user ID for 2FA setup
            session['user_id'] = user.id
            # Store the OAuth data to complete login after 2FA setup
            session['oauth_login'] = True
            return redirect(url_for('auth.setup_2fa'))
        
        # If user exists and has 2FA enabled, require verification
        if user.mfa_secret:
            session['user_id'] = user.id
            return redirect(url_for('auth.two_factor'))
            
        # If user exists but no 2FA, require setup
        if not user.mfa_secret:
            session['user_id'] = user.id
            session['oauth_login'] = True
            return redirect(url_for('auth.setup_2fa'))
        
        login_user(user)
        return redirect(url_for('main.index'))
    except Exception as e:
        current_app.logger.error(f"Google OAuth error: {str(e)}")
        flash('Authentication failed')
        return redirect(url_for('auth.login'))

@bp.route('/authorize/github')
def github_authorize():
    token = oauth.github.authorize_access_token()
    resp = oauth.github.get('user', token=token)
    user_info = resp.json()
    
    # Get user's email from GitHub
    emails_resp = oauth.github.get('user/emails', token=token)
    emails = emails_resp.json()
    primary_email = next((email['email'] for email in emails if email['primary']), None)
    
    if not primary_email:
        flash('Could not get email from GitHub')
        return redirect(url_for('auth.login'))
    
    user = User.query.filter_by(email=primary_email).first()
    if not user:
        # Create new user
        username = user_info.get('login', primary_email.split('@')[0])
        user = User(username=username, email=primary_email)
        user.set_password(secrets.token_urlsafe(32))  # Set a random secure password
        db.session.add(user)
        db.session.commit()
        
        # Store user ID for 2FA setup
        session['user_id'] = user.id
        # Store the OAuth data to complete login after 2FA setup
        session['oauth_login'] = True
        return redirect(url_for('auth.setup_2fa'))
    
    # If user exists and has 2FA enabled, require verification
    if user.mfa_secret:
        session['user_id'] = user.id
        return redirect(url_for('auth.two_factor'))
        
    # If user exists but no 2FA, require setup
    if not user.mfa_secret:
        session['user_id'] = user.id
        session['oauth_login'] = True
        return redirect(url_for('auth.setup_2fa'))
    
    login_user(user)
    return redirect(url_for('main.index')) 