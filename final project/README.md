# SecureDocs - Secure Document Vault

A secure web platform for document management with authentication, integrity, and encryption features.

## Features

- Modern authentication (OAuth 2.0 with Google & GitHub)
- Multi-Factor Authentication (2FA)
- Document encryption and digital signatures
- Secure transmission via HTTPS
- Role-based access control (RBAC)
- Data integrity verification

## Prerequisites

- Python 3.8+
- OpenSSL
- PostgreSQL/SQLite
- Node.js (for frontend build)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/securedocs.git
cd securedocs
```

2. Create and activate virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Generate SSL certificates:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

6. Initialize the database:

```bash
flask db init
flask db migrate
flask db upgrade
```

7. Run the application:

```bash
flask run --cert=cert.pem --key=key.pem
```

## Project Structure

```
securedocs/
├── app/                    # Application package
│   ├── __init__.py        # App initialization
│   ├── models.py          # Database models
│   ├── routes.py          # Route handlers
│   └── utils.py           # Utility functions
├── auth/                   # Authentication package
│   ├── __init__.py
│   ├── oauth.py           # OAuth handlers
│   └── mfa.py             # 2FA implementation
├── static/                 # Static files
│   ├── css/               # Stylesheets
│   └── js/                # JavaScript files
├── templates/             # HTML templates
├── certs/                 # SSL certificates
├── requirements.txt       # Python dependencies
└── README.md             # Project documentation
```

## Security Features

1. Authentication & Access Control

   - OAuth 2.0 Login (Google/GitHub)
   - SSO via Okta
   - 2FA with Google Authenticator
   - Session-based authentication
   - Role-based access control

2. Document Security

   - AES encryption for storage
   - SHA-256 hashing
   - Digital signatures
   - HMAC integrity verification

3. Transport Security
   - HTTPS/TLS
   - Certificate management
   - Protection against MITM attacks

## Team Members

- [Member 1]
- [Member 2]
- [Member 3]
- [Member 4]
- [Member 5]

## License

This project is licensed under the MIT License - see the LICENSE file for details.
