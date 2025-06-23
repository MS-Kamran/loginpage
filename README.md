# Google OAuth 2.0 Login Page with Flask

A secure, modern login page implementation using Google OAuth 2.0 with Flask backend. Features one-click Google Sign-In, JWT token management, and responsive design.

## Features

- 🔐 **Google OAuth 2.0 Integration** - Secure authentication with Google
- 🎨 **Modern UI/UX** - Responsive design with beautiful animations
- 🔒 **JWT Token Management** - Secure session handling
- 📱 **Mobile Responsive** - Works perfectly on all devices
- ⚡ **Fast & Lightweight** - Minimal dependencies
- 🛡️ **Security Best Practices** - HTTP-only cookies, CSRF protection

## Quick Start

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd loginpage
pip install -r requirements.txt
```

### 2. Google Cloud Console Setup

#### Step 1: Create a Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" → "New Project"
3. Enter project name and click "Create"

#### Step 2: Enable Google+ API
1. In the Google Cloud Console, go to "APIs & Services" → "Library"
2. Search for "Google+ API" and enable it
3. Also enable "Google Identity" if available

#### Step 3: Create OAuth 2.0 Credentials
1. Go to "APIs & Services" → "Credentials"
2. Click "+ CREATE CREDENTIALS" → "OAuth client ID"
3. If prompted, configure the OAuth consent screen first:
   - Choose "External" for testing
   - Fill in required fields (App name, User support email, Developer email)
   - Add your domain to "Authorized domains" (for production)
   - Add scopes: `email`, `profile`, `openid`
4. For OAuth client ID:
   - Application type: "Web application"
   - Name: "Login Page"
   - Authorized JavaScript origins:
     - `http://localhost:5000` (for development)
     - `https://yourdomain.com` (for production)
   - Authorized redirect URIs:
     - `http://localhost:5000/auth/google` (for development)
     - `https://yourdomain.com/auth/google` (for production)

#### Step 4: Get Your Client ID
1. Copy the "Client ID" from the credentials page
2. It should look like: `123456789-abcdefghijklmnop.apps.googleusercontent.com`

### 3. Configure the Application

Edit `app.py` and replace the placeholder:

```python
# Replace this line:
GOOGLE_CLIENT_ID = "your-google-client-id.apps.googleusercontent.com"

# With your actual Client ID:
GOOGLE_CLIENT_ID = "123456789-abcdefghijklmnop.apps.googleusercontent.com"
```

### 4. Run the Application

```bash
python app.py
```

Visit `http://localhost:5000` in your browser.

## Project Structure

```
loginpage/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/
│   ├── login.html        # Login page template
│   └── dashboard.html    # Post-login dashboard
└── static/
    └── css/
        └── style.css     # Styles for all pages
```

## Configuration Options

### Environment Variables (Recommended for Production)

Create a `.env` file:

```env
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
SECRET_KEY=your-super-secret-key-here
JWT_SECRET=your-jwt-secret-key-here
FLASK_ENV=production
```

Then modify `app.py` to use environment variables:

```python
import os
from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
app.secret_key = os.getenv('SECRET_KEY')
JWT_SECRET = os.getenv('JWT_SECRET')
```

### Security Configuration

For production, update these settings in `app.py`:

```python
# Enable secure cookies (HTTPS only)
response.set_cookie(
    'jwt_token',
    jwt_token,
    max_age=24*60*60,
    httponly=True,
    secure=True,        # Set to True for HTTPS
    samesite='Strict'   # Stricter CSRF protection
)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main route (redirects to login or dashboard) |
| `/login` | GET | Login page |
| `/auth/google` | POST | Google OAuth callback |
| `/dashboard` | GET | Protected dashboard page |
| `/logout` | GET | Logout and clear session |
| `/api/user` | GET | Get current user info (API) |

## Security Features

### 1. JWT Token Management
- Tokens expire after 24 hours
- HTTP-only cookies prevent XSS attacks
- Secure flag for HTTPS environments

### 2. Google OAuth 2.0
- Server-side token verification
- No client-side secrets
- Automatic token validation

### 3. Session Security
- Secure session keys
- CSRF protection
- SameSite cookie attributes

## Deployment

### Option 1: Heroku

1. Create `Procfile`:
```
web: python app.py
```

2. Update `app.py` for Heroku:
```python
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
```

3. Deploy:
```bash
heroku create your-app-name
heroku config:set GOOGLE_CLIENT_ID=your-client-id
heroku config:set SECRET_KEY=your-secret-key
git push heroku main
```

### Option 2: DigitalOcean App Platform

1. Create `app.yaml`:
```yaml
name: login-page
services:
- name: web
  source_dir: /
  github:
    repo: your-username/your-repo
    branch: main
  run_command: python app.py
  environment_slug: python
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: GOOGLE_CLIENT_ID
    value: your-client-id
  - key: SECRET_KEY
    value: your-secret-key
```

### Option 3: Traditional VPS

1. Install dependencies:
```bash
sudo apt update
sudo apt install python3 python3-pip nginx
pip3 install -r requirements.txt
```

2. Create systemd service:
```ini
# /etc/systemd/system/loginpage.service
[Unit]
Description=Login Page Flask App
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/loginpage
Environment=PATH=/var/www/loginpage/venv/bin
ExecStart=/var/www/loginpage/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

3. Configure Nginx:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Common Issues

1. **"Invalid Client ID" Error**
   - Verify your Client ID is correct
   - Check authorized origins in Google Console
   - Ensure the domain matches exactly

2. **"Redirect URI Mismatch"**
   - Add your redirect URI to Google Console
   - Check for typos in the URI
   - Ensure HTTP/HTTPS matches

3. **"Access Blocked" Error**
   - Complete OAuth consent screen configuration
   - Add test users if in development mode
   - Verify app is not suspended

4. **Token Verification Failed**
   - Check system time is synchronized
   - Verify Google+ API is enabled
   - Ensure network connectivity

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

app.run(debug=True)
```

## Best Practices

### Security
- Always use HTTPS in production
- Regularly rotate secret keys
- Implement rate limiting
- Monitor for suspicious activity
- Keep dependencies updated

### Performance
- Use a production WSGI server (Gunicorn, uWSGI)
- Implement caching for static assets
- Use a reverse proxy (Nginx, Apache)
- Monitor application performance

### Monitoring
- Set up error tracking (Sentry)
- Monitor login success/failure rates
- Track user session duration
- Log security events

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Search existing GitHub issues
3. Create a new issue with detailed information

## Changelog

### v1.0.0
- Initial release
- Google OAuth 2.0 integration
- JWT token management
- Responsive UI design
- Security best practices implementation