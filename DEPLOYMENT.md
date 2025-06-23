# Deployment Guide for Render

This guide will help you deploy your Flask login page application on Render.

## Prerequisites

1. Your code should be pushed to a GitHub repository
2. You need a Render account (free at https://render.com)
3. OAuth credentials from Google and Facebook (optional)

## Deployment Steps

### Method 1: Using render.yaml (Recommended)

1. **Connect your GitHub repository to Render:**
   - Go to https://render.com and sign up/login
   - Click "New" → "Blueprint"
   - Connect your GitHub account and select your repository
   - Render will automatically detect the `render.yaml` file

2. **Configure Environment Variables:**
   The following environment variables will be automatically created:
   - `FLASK_ENV` → `production`
   - `SECRET_KEY` → Auto-generated secure key
   - `JWT_SECRET` → Auto-generated secure key
   
   You need to manually add:
   - `GOOGLE_CLIENT_ID` → Your Google OAuth Client ID
   - `GOOGLE_CLIENT_SECRET` → Your Google OAuth Client Secret
   - `FACEBOOK_APP_ID` → Your Facebook App ID (optional)
   - `FACEBOOK_APP_SECRET` → Your Facebook App Secret (optional)

### Method 2: Manual Web Service Creation

1. **Create a new Web Service:**
   - Go to Render Dashboard
   - Click "New" → "Web Service"
   - Connect your GitHub repository

2. **Configure the service:**
   - **Name:** `loginpage` (or your preferred name)
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --bind 0.0.0.0:$PORT app:app`

3. **Add Environment Variables:**
   Go to the "Environment" tab and add:
   ```
   FLASK_ENV=production
   SECRET_KEY=your-secret-key-here
   JWT_SECRET=your-jwt-secret-here
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   FACEBOOK_APP_ID=your-facebook-app-id
   FACEBOOK_APP_SECRET=your-facebook-app-secret
   ```

## OAuth Configuration

### Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add your Render domain to authorized redirect URIs:
   - `https://your-app-name.onrender.com/auth/google`

### Facebook OAuth Setup
1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Add Facebook Login product
4. Add your Render domain to Valid OAuth Redirect URIs:
   - `https://your-app-name.onrender.com/auth/facebook`

## Important Notes

- **Free Tier Limitations:** Render's free tier may spin down your app after 15 minutes of inactivity
- **HTTPS:** Render automatically provides HTTPS for all deployments
- **Custom Domain:** You can add a custom domain in the Render dashboard
- **Logs:** Check the "Logs" tab in Render dashboard for debugging

## Troubleshooting

1. **Build Fails:** Check that all dependencies are in `requirements.txt`
2. **App Won't Start:** Verify the start command and check logs
3. **OAuth Issues:** Ensure redirect URIs match your Render domain
4. **Environment Variables:** Double-check all required variables are set

## Local Testing

Before deploying, test locally:
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_ENV=development
export SECRET_KEY=your-secret-key
# ... other variables

# Run with gunicorn (same as production)
gunicorn --bind 0.0.0.0:5001 app:app
```

Your app should be accessible at `http://localhost:5001`