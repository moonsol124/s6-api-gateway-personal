// gateway.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const session = require('express-session');
const axios = require('axios');
// const cookieParser = require('cookie-parser'); // Usually not needed directly if using express-session correctly

const app = express();
const gatewayPort = process.env.GATEWAY_PORT || 3002;

// --- Configuration Validation ---
const requiredEnvVars = [
    'PROPERTIES_SERVICE_URL',
    'OAUTH_SERVER_URL',
    'OAUTH_CLIENT_ID',
    'OAUTH_CLIENT_SECRET',
    'GATEWAY_CALLBACK_URI',
    'SESSION_SECRET',
    'FRONTEND_URL' // Good practice to ensure it's set for redirects
];

for (const varName of requiredEnvVars) {
    if (!process.env[varName]) {
        console.error(`FATAL ERROR: Environment variable ${varName} is not defined.`);
        process.exit(1);
    }
}

// --- Service URLs ---
const propertiesServiceUrl = process.env.PROPERTIES_SERVICE_URL;
const oauthServerUrl = process.env.OAUTH_SERVER_URL;
const userServiceUrl = process.env.USER_SERVICE_URL; // Add User Service URL

// --- Middleware ---

// CORS Configuration: Allow credentials (cookies) from your frontend origin
app.use(cors({
    origin: process.env.FRONTEND_URL, // Allow requests only from your frontend
    credentials: true // Important for cookies/sessions
}));

app.use(express.json());
// app.use(cookieParser()); // Usually not needed if session middleware is configured correctly
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session Configuration: Stores session data server-side, sends session ID cookie to browser
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        httpOnly: true, // Prevent client-side JS access to the cookie
        maxAge: 24 * 60 * 60 * 1000, // Example: 24 hours
        sameSite: 'lax' // Recommended for CSRF protection
    }
}));

// --- Authentication Middleware for Protected Routes ---
const requireAuth = (req, res, next) => {
    // Log the actual incoming request URL
    console.log(`[Auth Middleware] Checking auth for request: ${req.method} ${req.originalUrl}`);

    if (req.session && req.session.accessToken && Date.now() < req.session.tokenExpiresAt) {
        // User is authenticated and token is not expired
        req.headers['Authorization'] = `Bearer ${req.session.accessToken}`;
        // Log which request is getting the token attached
        console.log(`[Auth Middleware] Valid session. Attaching Bearer token for: ${req.method} ${req.originalUrl}`);
        next();
    } else {
        // Log details if authentication fails
        const reason = !(req.session && req.session.accessToken) ? "No session/token" : "Token expired";
        console.log(`[Auth Middleware] No valid session/token for ${req.method} ${req.originalUrl}. Reason: ${reason}. Denying access.`);
        res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
    }
};

console.log(`>>> Configuring proxy for /api/users. Target URL: [${userServiceUrl}]`); // ADD THIS LINE
 
// *** ADD USER PROXY ROUTE ***
app.use('/api/users', requireAuth, createProxyMiddleware({
    target: userServiceUrl,
    changeOrigin: true,
    pathRewrite: (path, req) => {
        const newPath = path.replace('/api/users', '/profiles');
        console.log(`[Gateway Path Rewrite] Original: ${path}, Rewritten: ${newPath}`); // Add logging
        return newPath;
    },
    onProxyReq: (proxyReq, req, res) => {
        // Auth header is added by requireAuth
        console.log(`[Gateway->Users] Proxying request to ${userServiceUrl}${proxyReq.path}`);
        console.log(`[Gateway->Users] Authorization Header Sent: ${proxyReq.getHeader('Authorization') ? 'Yes' : 'No'}`);
    },
    onError: (err, req, res) => {
       console.error('Users Proxy Error:', err);
       if (!res.headersSent) {
           res.status(503).json({ error: 'User service unavailable', details: err.message });
       }
    }
}));


// Use the new path prefix '/api/property-service'
const bodyParser = require('body-parser');
// Add this before your proxy middleware
app.use((req, res, next) => {
    if (req.url.startsWith('/api/property-service')) {
      console.log(`[Debug] ${req.method} request to ${req.url}`);
      console.log(`[Debug] Headers: ${JSON.stringify(req.headers)}`);
      if (req.body) console.log(`[Debug] Body: ${JSON.stringify(req.body)}`);
    }
    next();
  });

  // Parse JSON only for non-proxy routes
app.use((req, res, next) => {
  if (!req.url.startsWith('/api/property-service')) {
    express.json()(req, res, next);
  } else {
    next();
  }
});

// For the proxy route, use raw body parsing
// Then set up the proxy with proper body handling
app.use('/api/property-service', requireAuth, createProxyMiddleware({
    target: propertiesServiceUrl,
    changeOrigin: true,
    pathRewrite: {
      '^/api/property-service': '/properties',
    },
    // IMPORTANT: Don't manipulate the onProxyReq for now
    // The default behavior should work for JSON bodies
    onProxyReq: function(proxyReq, req, res) {
      // Only log, don't modify the request
      console.log(`[Gateway->Property Service] Proxying ${req.method} request to ${propertiesServiceUrl}${proxyReq.path}`);
      console.log(`[Gateway->Property Service] Authorization Header Sent: ${proxyReq.getHeader('Authorization') ? 'Yes' : 'No'}`);
    },
    onError: (err, req, res) => {
      console.error('Property Service Proxy Error:', err);
      if (!res.headersSent) {
        res.status(503).json({ error: 'Property service unavailable', details: err.message });
      }
    }
  }));
// --- Basic Route for Testing Gateway ---
app.get('/', (req, res) => {
    res.send('API Gateway is running');
});

// --- Authentication Routes ---

// 1. Callback URL: Handles the redirect from the OAuth server after user grants consent
app.get('/auth/callback', async (req, res) => {
    const { code, error, error_description } = req.query;
    console.log('[Gateway /auth/callback] Received callback. Query:', req.query); // Log incoming query

    if (error) {
        console.error('[Gateway /auth/callback] OAuth Error received directly:', { error, error_description });
        // Redirect to frontend with error information
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(error_description || 'Unknown error')}`);
    }

    if (!code) {
        console.error('[Gateway /auth/callback] OAuth Callback Error: No authorization code received.');
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=missing_code`);
    }

    console.log('[Gateway /auth/callback] Extracted code:', code);

    // Prepare payload for token request
    const tokenPayload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: process.env.GATEWAY_CALLBACK_URI, // Must match exactly what was used in /authorize and registered
        client_id: process.env.OAUTH_CLIENT_ID,
        client_secret: process.env.OAUTH_CLIENT_SECRET
    });

    console.log('[Gateway /auth/callback] Sending request to /token endpoint...');
    console.log('[Gateway /auth/callback]   -> URL:', `${oauthServerUrl}/token`);
    console.log('[Gateway /auth/callback]   -> Method: POST');
    console.log('[Gateway /auth/callback]   -> Payload (URL Encoded):', tokenPayload.toString());
    console.log('[Gateway /auth/callback]   -> Headers: Content-Type: application/x-www-form-urlencoded');

    try {
        // 2. Exchange authorization code for access token
        const tokenResponse = await axios.post(`${oauthServerUrl}/token`, tokenPayload, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            // Optional: Add timeout
            // timeout: 10000 // 10 seconds
        });

        console.log('[Gateway /auth/callback] Token response received successfully.');
        console.log('[Gateway /auth/callback]   -> Status:', tokenResponse.status);
        console.log('[Gateway /auth/callback]   -> Data:', tokenResponse.data);

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        if (!access_token) {
            // Should ideally not happen if status is 200, but check defensively
            console.error('[Gateway /auth/callback] Token Exchange Error: No access token found in response data.');
             return res.redirect(`${process.env.FRONTEND_URL}/login?error=token_exchange_failed&error_description=No access token received`);
        }

        // 3. Store token details in the session
        req.session.accessToken = access_token;
        req.session.refreshToken = refresh_token;
        req.session.tokenExpiresAt = Date.now() + (expires_in * 1000);

        console.log('[Gateway /auth/callback] Session established successfully.');
        // console.log('[Gateway /auth/callback] Session ID:', req.session.id); // Optional: Log session ID

        // 4. Redirect user back to the frontend dashboard
        // Consider where the user intended to go, if stored in session before /authorize redirect
        const redirectTarget = process.env.FRONTEND_URL + '/'; // Default to root/dashboard
        console.log(`[Gateway /auth/callback] Redirecting user to: ${redirectTarget}`);
        res.redirect(redirectTarget);

    } catch (err) {
        // Log detailed error information from the token exchange attempt
        console.error('!!! [Gateway /auth/callback] Error during OAuth token exchange:');
        let errorMsg = 'token_exchange_error';
        let errorDesc = 'Failed to exchange authorization code for token.';

         if (err.response) {
            // Error response received from the OAuth server (/token endpoint)
            console.error('[Gateway /auth/callback]   -> OAuth Server Error Status:', err.response.status);
            console.error('[Gateway /auth/callback]   -> OAuth Server Error Data:', err.response.data);
            // Use specific error from OAuth server if available
            errorMsg = err.response.data.error || errorMsg;
            errorDesc = err.response.data.error_description || errorDesc;
         } else if (err.request) {
             // The request was made but no response was received
             console.error('[Gateway /auth/callback]   -> No response received from OAuth server:', err.request);
             errorDesc = 'No response received from authentication server.';
         } else {
             // Something happened in setting up the request that triggered an Error
             console.error('[Gateway /auth/callback]   -> Error setting up token request:', err.message);
             errorDesc = 'Error occurred while preparing authentication request.';
         }
         // Log the error object itself for more details if needed
         // console.error(err);

        // Redirect to frontend with specific error info
        res.redirect(`${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(errorMsg)}&error_description=${encodeURIComponent(errorDesc)}`);
    }
});

// 5. Check Authentication Status Endpoint
app.get('/auth/status', (req, res) => {
    if (req.session && req.session.accessToken && Date.now() < req.session.tokenExpiresAt) {
        // Optionally, you could add logic here to fetch basic user info if needed
        res.json({ authenticated: true /*, user: { id: req.session.userId } */ });
    } else {
        // If token is expired or missing, consider it not authenticated
        // Potential future enhancement: Use refresh token here if available and token is expired
        res.json({ authenticated: false });
    }
});

// 6. Logout Endpoint
app.get('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
             return res.status(500).json({ error: 'Could not log out' });
        }
        // Optional: Clear the session cookie explicitly
        res.clearCookie('connect.sid'); // Default session cookie name used by express-session
        console.log('User logged out, session destroyed.');
        // Send a success response or redirect to the frontend's logged-out page
        // res.status(200).json({ message: 'Logged out successfully' });
        res.redirect(`${process.env.FRONTEND_URL}/login?logout=success`);
    });
    // Optional: Implement OAuth server token revocation if the server supports it
});



// --- Proxy Routes ---


// --- Add proxies for other *protected* services similarly ---
/*
const anotherServiceUrl = process.env.ANOTHER_SERVICE_URL;
if (anotherServiceUrl) {
    app.use('/api/another-service', requireAuth, createProxyMiddleware({ // Add requireAuth
        target: anotherServiceUrl,
        changeOrigin: true,
        pathRewrite: {
            '^/api/another-service': '/internal-path',
        },
        // ... other options
    }));
}
*/

// --- 404 Handler for unmatched routes on the gateway ---
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found on Gateway' });
});

// --- Start the Gateway Server ---
app.listen(gatewayPort, () => {
    console.log(`API Gateway listening at http://localhost:${gatewayPort}`);
    console.log(`Frontend URL configured as: ${process.env.FRONTEND_URL}`);
    console.log(`OAuth Server URL configured as: ${process.env.OAUTH_SERVER_URL}`);
    console.log(`OAuth Callback URI configured as: ${process.env.GATEWAY_CALLBACK_URI}`);
    console.log(`Proxying /api/properties -> ${propertiesServiceUrl}/properties (Authentication Required)`);
});