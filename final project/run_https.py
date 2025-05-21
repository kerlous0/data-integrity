from app import create_app
import ssl

app = create_app()

if __name__ == '__main__':
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('ssl/cert.pem', 'ssl/key.pem')
    
    # Enable HTTPS-only mode
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['SESSION_COOKIE_SECURE'] = True
    
    # Run app with HTTPS
    app.run(
        host='127.0.0.1',  # Only allow local connections
        port=5443,         # Use non-privileged port
        ssl_context=context,
        debug=False        # Disable debug mode in production
    ) 