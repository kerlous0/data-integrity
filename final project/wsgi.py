from app import create_app, db
from app.models import User, Document, AuditLog

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Document': Document,
        'AuditLog': AuditLog
    }

if __name__ == '__main__':
    app.run() 