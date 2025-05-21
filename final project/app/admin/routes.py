from flask import render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app import db
from app.admin import bp
from app.models import User, Document, AuditLog
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/')
@login_required
@admin_required
def index():
    users = User.query.all()
    documents = Document.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('admin/index.html',
                         title='Admin Dashboard',
                         users=users,
                         documents=documents,
                         logs=logs)

@bp.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('admin/users.html', title='User Management', users=users)

@bp.route('/user/<int:id>')
@login_required
@admin_required
def user(id):
    user = User.query.get_or_404(id)
    documents = Document.query.filter_by(user_id=id).all()
    logs = AuditLog.query.filter_by(user_id=id).order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin/user.html',
                         title=f'User: {user.username}',
                         user=user,
                         documents=documents,
                         logs=logs)

@bp.route('/user/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        user.is_active = bool(request.form.get('active'))
        
        # Handle password change if provided
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password:
            if new_password == confirm_password:
                user.set_password(new_password)
            else:
                flash('New passwords do not match')
                return redirect(url_for('admin.edit_user', id=user.id))
        
        db.session.commit()
        
        # Log the action
        log = AuditLog(
            user_id=current_user.id,
            action='edit_user',
            details=f'Modified user: {user.username}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('User updated successfully')
        return redirect(url_for('admin.user', id=user.id))
    
    return render_template('admin/edit_user.html',
                         title=f'Edit User: {user.username}',
                         user=user)

@bp.route('/user/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    
    # Don't allow deleting self
    if user.id == current_user.id:
        flash('Cannot delete own account')
        return redirect(url_for('admin.users'))
    
    # Delete user's documents
    documents = Document.query.filter_by(user_id=id).all()
    for doc in documents:
        db.session.delete(doc)
    
    # Log the action
    log = AuditLog(
        user_id=current_user.id,
        action='delete_user',
        details=f'Deleted user: {user.username}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully')
    return redirect(url_for('admin.users'))

@bp.route('/logs')
@login_required
@admin_required
def logs():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)
    return render_template('admin/logs.html',
                         title='Audit Logs',
                         logs=logs)

@bp.route('/documents')
@login_required
@admin_required
def documents():
    page = request.args.get('page', 1, type=int)
    documents = Document.query.order_by(Document.uploaded_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template('admin/documents.html',
                         title='All Documents',
                         documents=documents) 