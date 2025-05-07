// gateway.js
require('dotenv').config(); // For local development
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const session = require('express-session');
const axios = require('axios');

const app = express();
const gatewayPort = process.env.PORT || 3002; // Standardize to PORT like other services

// --- Determine if running in a production-like environment (for cookie settings) ---
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// --- Configuration Validation ---
const requiredEnvVars = [
    'PROPERTIES_SERVICE_URL',
    'USER_SERVICE_URL', // Added User Service URL here for validation
    'OAUTH_SERVER_URL',
    'OAUTH_CLIENT_ID',
    'OAUTH_CLIENT_SECRET',
    'GATEWAY_PUBLIC_CALLBACK_URI', // Renamed for clarity: this is the public URI
    'SESSION_SECRET',
    'FRONTEND_URL'
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
const userServiceUrl = process.env.USER_SERVICE_URL;

// --- Middleware ---

// CORS Configuration
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));

// Standard body parsers
app.use(express.json({ limit: '10mb' })); // For JSON payloads
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // For URL-encoded payloads

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: IS_PRODUCTION, // true if https, false if http
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: IS_PRODUCTION ? 'None' : 'Lax' // 'None' for cross-site (requires Secure=true), 'Lax' for same-site or dev
    }
}));
console.log(`Session cookie configured with: secure=${IS_PRODUCTION}, sameSite=${IS_PRODUCTION ? 'None' : 'Lax'}`);


// --- Authentication Middleware for Protected Routes ---
const requireAuth = (req, res, next) => {
    console.log(`[Auth Middleware] Checking auth for request: ${req.method} ${req.originalUrl}`);
    // Check for session, access token, and if the token is expired
    if (req.session && req.session.accessToken && Date.now() < req.session.tokenExpiresAt) {
        req.headers['authorization'] = `Bearer ${req.session.accessToken}`; // Note: http-proxy-middleware uses 'authorization' not 'Authorization' by default for outgoing
        console.log(`[Auth Middleware] Valid session. Attaching Bearer token for: ${req.method} ${req.originalUrl}`);
        next();
    } else {
        const reason = !(req.session && req.session.accessToken) ? "No session/token" : "Token expired";
        console.log(`[Auth Middleware] No valid session/token for ${req.method} ${req.originalUrl}. Reason: ${reason}. Denying access.`);
        res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
    }
};

// --- Basic Route for Testing Gateway ---
app.get('/', (req, res) => {
    res.send(`API Gateway is running. IS_PRODUCTION: ${IS_PRODUCTION}`);
});

// --- Authentication Routes ---

// 1. Callback URL: Handles the redirect from the OAuth server
app.get('/auth/callback', async (req, res) => {
    const { code, error, error_description } = req.query;
    console.log('[Gateway /auth/callback] Received callback. Query:', req.query);

    if (error) {
        console.error('[Gateway /auth/callback] OAuth Error received directly:', { error, error_description });
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(error_description || 'Unknown error')}`);
    }

    if (!code) {
        console.error('[Gateway /auth/callback] OAuth Callback Error: No authorization code received.');
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=missing_code`);
    }

    console.log('[Gateway /auth/callback] Extracted code:', code);

    const tokenPayload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code.toString(), // Ensure code is a string
        redirect_uri: process.env.GATEWAY_PUBLIC_CALLBACK_URI, // CRITICAL: Use the public callback URI
        client_id: process.env.OAUTH_CLIENT_ID,
        client_secret: process.env.OAUTH_CLIENT_SECRET
    });

    console.log('[Gateway /auth/callback] Sending request to /token endpoint...');
    console.log('[Gateway /auth/callback]   -> URL:', `${oauthServerUrl}/token`);
    console.log('[Gateway /auth/callback]   -> Payload (URL Encoded):', tokenPayload.toString());

    try {
        const tokenResponse = await axios.post(`${oauthServerUrl}/token`, tokenPayload.toString(), { // Send as string
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('[Gateway /auth/callback] Token response received successfully.');
        console.log('[Gateway /auth/callback]   -> Status:', tokenResponse.status);
        console.log('[Gateway /auth/callback]   -> Data:', tokenResponse.data);

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        if (!access_token) {
            console.error('[Gateway /auth/callback] Token Exchange Error: No access token found.');
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=token_exchange_failed&error_description=No access token received`);
        }

        req.session.accessToken = access_token;
        req.session.refreshToken = refresh_token; // Store refresh token if you plan to use it
        req.session.tokenExpiresAt = Date.now() + ((expires_in || 3600) * 1000); // Use expires_in, default to 1hr

        console.log('[Gateway /auth/callback] Session established successfully. Session ID:', req.session.id);
        
        const redirectTarget = req.session.originalUrl || process.env.FRONTEND_URL + '/'; // Redirect to original URL or default
        delete req.session.originalUrl; // Clean up
        console.log(`[Gateway /auth/callback] Redirecting user to: ${redirectTarget}`);
        res.redirect(redirectTarget);

    } catch (err) {
        console.error('!!! [Gateway /auth/callback] Error during OAuth token exchange:');
        let errorMsg = 'token_exchange_error';
        let errorDesc = 'Failed to exchange authorization code for token.';

        if (err.response) {
            console.error('[Gateway /auth/callback]   -> OAuth Server Error Status:', err.response.status);
            console.error('[Gateway /auth/callback]   -> OAuth Server Error Data:', err.response.data);
            errorMsg = err.response.data.error || errorMsg;
            errorDesc = err.response.data.error_description || errorDesc;
        } else if (err.request) {
            console.error('[Gateway /auth/callback]   -> No response received from OAuth server (Network Error or Timeout)');
            errorDesc = 'No response received from authentication server.';
        } else {
            console.error('[Gateway /auth/callback]   -> Error setting up token request:', err.message);
            errorDesc = 'Error occurred while preparing authentication request.';
        }
        res.redirect(`${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(errorMsg)}&error_description=${encodeURIComponent(errorDesc)}`);
    }
});

// 2. Start OAuth Flow (Optional: if gateway initiates it)
app.get('/auth/login', (req, res) => {
    // Store the original URL the user was trying to access, if any
    if (req.query.redirect) {
        req.session.originalUrl = req.query.redirect;
    }

    const authorizationUrl = new URL(`${oauthServerUrl}/authorize`);
    authorizationUrl.searchParams.append('response_type', 'code');
    authorizationUrl.searchParams.append('client_id', process.env.OAUTH_CLIENT_ID);
    authorizationUrl.searchParams.append('redirect_uri', process.env.GATEWAY_PUBLIC_CALLBACK_URI);
    // authorizationUrl.searchParams.append('scope', 'openid profile email'); // Add scopes as needed
    // authorizationUrl.searchParams.append('state', 'some_random_state_string'); // Recommended for CSRF protection

    console.log(`[Gateway /auth/login] Redirecting user to OAuth server: ${authorizationUrl.toString()}`);
    res.redirect(authorizationUrl.toString());
});


// 3. Check Authentication Status Endpoint
app.get('/auth/status', (req, res) => {
    console.log('[Gateway /auth/status] Checking auth status. Session ID:', req.sessionID);
    console.log('[Gateway /auth/status] Session Access Token:', req.session.accessToken ? 'Exists' : 'Missing');
    console.log('[Gateway /auth/status] Session Expires At:', req.session.tokenExpiresAt ? new Date(req.session.tokenExpiresAt) : 'N/A');

    if (req.session && req.session.accessToken && Date.now() < req.session.tokenExpiresAt) {
        res.json({ authenticated: true /*, user: { id: req.session.userId } */ });
    } else {
        res.json({ authenticated: false });
    }
});

// 4. Logout Endpoint
app.get('/auth/logout', (req, res) => {
    const sessionId = req.sessionID;
    req.session.destroy((err) => {
        if (err) {
            console.error(`[Gateway /auth/logout] Error destroying session ${sessionId}:`, err);
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.clearCookie('connect.sid', { path: '/' }); // Ensure path matches how it was set
        console.log(`[Gateway /auth/logout] User logged out, session ${sessionId} destroyed.`);
        res.redirect(`${process.env.FRONTEND_URL}/login?logout=success`);
        // TODO: Optionally, redirect to OAuth server's logout endpoint if it supports RP-initiated logout
        // This would log the user out of the OAuth server itself, not just your app's session.
        // const oauthLogoutUrl = `${oauthServerUrl}/logout?post_logout_redirect_uri=${process.env.FRONTEND_URL}&client_id=${process.env.OAUTH_CLIENT_ID}`;
        // res.redirect(oauthLogoutUrl);
    });
});


// --- Proxy Routes ---
console.log(`Configuring proxy for /api/users. Target: [${userServiceUrl}]`);
app.use('/api/users', requireAuth, createProxyMiddleware({
    target: userServiceUrl,
    changeOrigin: true,
    pathRewrite: (path, req) => {
        const newPath = path.replace('/api/users', '/profiles'); // Assuming /profiles is the target on user-service
        console.log(`[Gateway Path Rewrite /api/users] Original: ${path}, Rewritten: ${newPath}`);
        return newPath;
    },
    onProxyReq: (proxyReq, req, res) => {
        console.log(`[Gateway->Users] Proxying request to ${userServiceUrl}${proxyReq.path} with auth header: ${proxyReq.getHeader('authorization') ? 'Yes' : 'No'}`);
    },
    onError: (err, req, res) => {
       console.error('[Gateway->Users] Proxy Error:', err.message);
       if (!res.headersSent) {
           res.status(503).json({ error: 'User service unavailable' });
       }
    }
}));

console.log(`Configuring proxy for /api/property-service. Target: [${propertiesServiceUrl}]`);
app.use('/api/property-service', requireAuth, createProxyMiddleware({
    target: propertiesServiceUrl,
    changeOrigin: true,
    pathRewrite: {
      '^/api/property-service': '/properties', // Assuming /properties is the target on properties-service
    },
    onProxyReq: (proxyReq, req, res) => {
      console.log(`[Gateway->Property Service] Proxying ${req.method} request to ${propertiesServiceUrl}${proxyReq.path} with auth header: ${proxyReq.getHeader('authorization') ? 'Yes' : 'No'}`);
    },
    onError: (err, req, res) => {
      console.error('[Gateway->Property Service] Proxy Error:', err.message);
      if (!res.headersSent) {
        res.status(503).json({ error: 'Property service unavailable' });
      }
    }
}));


// --- 404 Handler for unmatched API gateway routes ---
app.use((req, res) => {
    console.log(`[Gateway 404] Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ error: 'Not Found on API Gateway' });
});

// --- Global Error Handler (Optional but good practice) ---
app.use((err, req, res, next) => {
    console.error("!!! [Gateway Global Error Handler] An unexpected error occurred:", err);
    if (!res.headersSent) {
        res.status(500).json({ error: "Internal Server Error", message: "An unexpected error occurred on the gateway." });
    }
});


// --- Start the Gateway Server ---
app.listen(gatewayPort, () => {
    console.log("-------------------------------------------------------");
    console.log(`API Gateway listening at http://localhost:${gatewayPort} (inside container)`);
    console.log(`NODE_ENV: ${process.env.NODE_ENV || 'development (default)'}`);
    console.log(`IS_PRODUCTION: ${IS_PRODUCTION}`);
    console.log(`Frontend URL (for redirects): ${process.env.FRONTEND_URL}`);
    console.log(`OAuth Server URL (for backend calls): ${oauthServerUrl}`);
    console.log(`OAuth Client ID: ${process.env.OAUTH_CLIENT_ID ? 'Loaded' : 'MISSING!'}`);
    console.log(`Gateway Public Callback URI (for /token): ${process.env.GATEWAY_PUBLIC_CALLBACK_URI}`);
    console.log("--- Proxied Service URLs ---");
    console.log(`  User Service: ${userServiceUrl}`);
    console.log(`  Properties Service: ${propertiesServiceUrl}`);
    console.log("-------------------------------------------------------");
});