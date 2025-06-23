from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from datetime import datetime, timedelta
import jwt
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'your-google-client-id.apps.googleusercontent.com')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'your-google-client-secret')

# Facebook OAuth Configuration
FACEBOOK_APP_ID = os.environ.get('FACEBOOK_APP_ID', 'your-facebook-app-id')
FACEBOOK_APP_SECRET = os.environ.get('FACEBOOK_APP_SECRET', 'your-facebook-app-secret')
JWT_SECRET = secrets.token_hex(32)  # For JWT token generation
JWT_ALGORITHM = "HS256"

# In-memory user storage (use a database in production)
users = {}

def verify_google_token(token):
    """Verify Google ID token and return user info"""
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, requests.Request(), GOOGLE_CLIENT_ID
        )
        
        # Check if token is from Google
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        return idinfo
    except ValueError as e:
        print(f"Token verification failed: {e}")
        return None

def generate_jwt_token(user_info):
    """Generate JWT token for authenticated user"""
    payload = {
        'user_id': user_info.get('sub') or user_info.get('id'),
        'email': user_info.get('email', ''),
        'name': user_info.get('name', ''),
        'provider': user_info.get('provider', 'google'),
        'exp': datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token):
    """Verify JWT token and return user info"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

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
            session['user'] = user_info
            return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))

@app.route('/login')
def login():
    """Login page with Google Sign-In"""
    return render_template('login.html', 
                         google_client_id=GOOGLE_CLIENT_ID,
                         facebook_app_id=FACEBOOK_APP_ID)

@app.route('/auth/google', methods=['POST'])
def google_auth():
    """Handle Google OAuth callback"""
    try:
        # Get the credential from the request
        credential = request.json.get('credential')
        if not credential:
            return jsonify({'error': 'No credential provided'}), 400
        
        # Verify the Google ID token
        google_user_info = verify_google_token(credential)
        if not google_user_info:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Format user info for consistency
        user_info = {
            'sub': google_user_info['sub'],
            'id': google_user_info['sub'],
            'name': google_user_info.get('name', ''),
            'email': google_user_info.get('email', ''),
            'picture': google_user_info.get('picture', ''),
            'provider': 'google'
        }
        
        # Generate JWT token for the user
        jwt_token = generate_jwt_token(user_info)
        
        # Store user info in session
        session['user'] = user_info
        session['jwt_token'] = jwt_token
        
        return jsonify({
            'success': True,
            'user': user_info,
            'token': jwt_token,
            'redirect': '/dashboard'
        })
    
    except Exception as e:
        print(f"Authentication error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/auth/facebook')
def facebook_login():
    """Redirect to Facebook OAuth"""
    facebook_auth_url = (
        f"https://www.facebook.com/v18.0/dialog/oauth?"
        f"client_id={FACEBOOK_APP_ID}&"
        f"redirect_uri={request.url_root}auth/facebook/callback&"
        f"scope=email,public_profile&"
        f"response_type=code"
    )
    return redirect(facebook_auth_url)

@app.route('/auth/facebook/callback')
def facebook_callback():
    """Handle Facebook OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return redirect('/login?error=facebook_auth_failed')
        
        # Exchange code for access token
        token_url = "https://graph.facebook.com/v18.0/oauth/access_token"
        token_data = {
            'client_id': FACEBOOK_APP_ID,
            'client_secret': FACEBOOK_APP_SECRET,
            'redirect_uri': f"{request.url_root}auth/facebook/callback",
            'code': code
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            return redirect('/login?error=facebook_token_failed')
        
        access_token = token_json['access_token']
        
        # Get user info from Facebook
        user_url = f"https://graph.facebook.com/v18.0/me?fields=id,name,email,picture&access_token={access_token}"
        user_response = requests.get(user_url)
        user_data = user_response.json()
        
        if 'error' in user_data:
            return redirect('/login?error=facebook_user_failed')
        
        # Format user info similar to Google
        user_info = {
            'sub': user_data['id'],
            'id': user_data['id'],
            'name': user_data.get('name', ''),
            'email': user_data.get('email', ''),
            'picture': user_data.get('picture', {}).get('data', {}).get('url', ''),
            'provider': 'facebook'
        }
        
        # Generate JWT token
        jwt_token = generate_jwt_token(user_info)
        
        # Store in session
        session['user'] = user_info
        session['jwt_token'] = jwt_token
        
        return redirect('/dashboard')
    
    except Exception as e:
        print(f"Facebook authentication error: {e}")
        return redirect('/login?error=facebook_auth_failed')

@app.route('/dashboard')
def dashboard():
    """Protected dashboard page"""
    # Check if user is authenticated
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    session.clear()
    response = redirect(url_for('login'))
    response.set_cookie('jwt_token', '', expires=0)  # Clear JWT cookie
    return response

@app.route('/api/user')
def api_user():
    """API endpoint to get current user info"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify(session['user'])

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    # Get port from environment variable (for deployment) or use 5001 for local development
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(debug=debug, host='0.0.0.0', port=port)