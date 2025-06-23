from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from datetime import datetime, timedelta
import jwt
import secrets
import logging
from functools import wraps
from config import get_config

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config_class = get_config()
app.config.from_object(config_class)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory user storage (use a database in production)
users = {}

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# Rate limiting (simple in-memory implementation)
rate_limit_storage = {}

def rate_limit(max_requests=5, window=300):  # 5 requests per 5 minutes
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            current_time = datetime.utcnow()
            
            # Clean old entries
            cutoff_time = current_time - timedelta(seconds=window)
            rate_limit_storage[client_ip] = [
                timestamp for timestamp in rate_limit_storage.get(client_ip, [])
                if timestamp > cutoff_time
            ]
            
            # Check rate limit
            if len(rate_limit_storage.get(client_ip, [])) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
            
            # Add current request
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = []
            rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def verify_google_token(token):
    """Verify Google ID token and return user info"""
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, requests.Request(), app.config['GOOGLE_CLIENT_ID']
        )
        
        # Check if token is from Google
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        logger.info(f"Successfully verified Google token for user: {idinfo.get('email')}")
        return idinfo
    except ValueError as e:
        logger.error(f"Token verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {e}")
        return None

def generate_jwt_token(user_info):
    """Generate JWT token for authenticated user"""
    payload = {
        'user_id': user_info['sub'],
        'email': user_info['email'],
        'name': user_info['name'],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + app.config['JWT_EXPIRATION']
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm=app.config['JWT_ALGORITHM'])

def verify_jwt_token(token):
    """Verify JWT token and return user info"""
    try:
        payload = jwt.decode(
            token, 
            app.config['JWT_SECRET'], 
            algorithms=[app.config['JWT_ALGORITHM']]
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None

def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session first
        if 'user' in session:
            return f(*args, **kwargs)
        
        # Check JWT token
        jwt_token = request.cookies.get('jwt_token')
        if jwt_token:
            user_info = verify_jwt_token(jwt_token)
            if user_info:
                session['user'] = {
                    'id': user_info['user_id'],
                    'email': user_info['email'],
                    'name': user_info['name']
                }
                return f(*args, **kwargs)
        
        return redirect(url_for('login'))
    return decorated_function

@app.route('/')
def index():
    """Main route - redirect to login or dashboard based on authentication"""
    # Check if user is authenticated via session
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    # Check if user has valid JWT token
    jwt_token = request.cookies.get('jwt_token')
    if jwt_token:
        user_info = verify_jwt_token(jwt_token)
        if user_info:
            session['user'] = {
                'id': user_info['user_id'],
                'email': user_info['email'],
                'name': user_info['name']
            }
            return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))

@app.route('/login')
def login():
    """Login page with Google Sign-In"""
    # If already authenticated, redirect to dashboard
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    return render_template('login.html', google_client_id=app.config['GOOGLE_CLIENT_ID'])

@app.route('/auth/google', methods=['POST'])
@rate_limit(max_requests=10, window=300)  # 10 attempts per 5 minutes
def google_auth():
    """Handle Google OAuth callback"""
    try:
        # Validate request
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        # Get the ID token from the request
        token = request.json.get('credential')
        
        if not token:
            logger.warning("Authentication attempt without token")
            return jsonify({'error': 'No token provided'}), 400
        
        # Verify the Google ID token
        user_info = verify_google_token(token)
        
        if not user_info:
            logger.warning(f"Invalid token from IP: {request.remote_addr}")
            return jsonify({'error': 'Invalid token'}), 401
        
        # Store user information
        user_id = user_info['sub']
        users[user_id] = {
            'id': user_id,
            'email': user_info['email'],
            'name': user_info['name'],
            'picture': user_info.get('picture', ''),
            'last_login': datetime.utcnow().isoformat(),
            'login_count': users.get(user_id, {}).get('login_count', 0) + 1
        }
        
        # Create session
        session['user'] = users[user_id]
        session.permanent = True
        
        # Generate JWT token
        jwt_token = generate_jwt_token(user_info)
        
        response = make_response(jsonify({
            'success': True,
            'redirect_url': url_for('dashboard'),
            'user': {
                'name': user_info['name'],
                'email': user_info['email']
            }
        }))
        
        # Set JWT token as HTTP-only cookie for security
        response.set_cookie(
            'jwt_token',
            jwt_token,
            max_age=int(app.config['JWT_EXPIRATION'].total_seconds()),
            httponly=True,
            secure=app.config['SESSION_COOKIE_SECURE'],
            samesite=app.config['SESSION_COOKIE_SAMESITE']
        )
        
        logger.info(f"Successful login for user: {user_info['email']}")
        return response
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard page"""
    user = session['user']
    
    # Update last seen
    if user['id'] in users:
        users[user['id']]['last_seen'] = datetime.utcnow().isoformat()
    
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    user_email = session.get('user', {}).get('email', 'Unknown')
    session.clear()
    
    response = make_response(redirect(url_for('login')))
    response.set_cookie('jwt_token', '', expires=0)  # Clear JWT cookie
    
    logger.info(f"User logged out: {user_email}")
    return response

@app.route('/api/user')
@login_required
def api_user():
    """API endpoint to get current user info"""
    user = session['user']
    
    # Return safe user info (exclude sensitive data)
    safe_user_info = {
        'id': user['id'],
        'name': user['name'],
        'email': user['email'],
        'picture': user.get('picture', ''),
        'last_login': user.get('last_login'),
        'login_count': user.get('login_count', 1)
    }
    
    return jsonify(safe_user_info)

@app.route('/api/refresh-token', methods=['POST'])
@login_required
def refresh_token():
    """Refresh JWT token"""
    user = session['user']
    
    # Generate new JWT token
    user_info = {
        'sub': user['id'],
        'email': user['email'],
        'name': user['name']
    }
    
    new_token = generate_jwt_token(user_info)
    
    response = make_response(jsonify({'success': True, 'message': 'Token refreshed'}))
    response.set_cookie(
        'jwt_token',
        new_token,
        max_age=int(app.config['JWT_EXPIRATION'].total_seconds()),
        httponly=True,
        secure=app.config['SESSION_COOKIE_SECURE'],
        samesite=app.config['SESSION_COOKIE_SAMESITE']
    )
    
    logger.info(f"Token refreshed for user: {user['email']}")
    return response

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('login.html', 
                         google_client_id=app.config['GOOGLE_CLIENT_ID'],
                         error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limit errors"""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

if __name__ == '__main__':
    # Create directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    
    # Get port from environment (for deployment platforms)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    if app.config['DEBUG']:
        app.run(debug=True, host='0.0.0.0', port=port)
    else:
        # Production settings
        app.run(host='0.0.0.0', port=port)