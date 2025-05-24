// gateway.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const axios = require('axios');
const jwt = require('jsonwebtoken'); // Required for JWT validation middleware

const app = express();
const gatewayPort = process.env.GATEWAY_PORT || 3002;

// --- Configuration Validation ---
const requiredEnvVars = [
    'PROPERTIES_SERVICE_URL',
    'OAUTH_SERVER_URL',
    'OAUTH_CLIENT_ID',
    'OAUTH_CLIENT_SECRET',
    'GATEWAY_CALLBACK_URI',
    'FRONTEND_URL',
    'JWT_SECRET'
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

// --- JWT Secret Key ---
const jwtSecret = process.env.JWT_SECRET;

// --- Middleware ---

// CORS Configuration: Restrict origin to your frontend URL
app.use(cors({
    origin: process.env.FRONTEND_URL,
}));

// ********************************************************************
// --- CORRECTED BODY PARSING ---
// Body parsing middleware should ONLY be applied to routes
// that process the body directly in the Gateway.
// Proxied routes should receive the raw body stream.
// These parsers will be applied specifically to the /auth routes below.
// ********************************************************************


// --- JWT Authentication Middleware (Define but DON'T apply globally) ---
const requireAuth = (req, res, next) => {
    console.log(`[Auth Middleware] Checking auth for request: ${req.method} ${req.originalUrl}`);

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        console.log(`[Auth Middleware] No Authorization header found for ${req.method} ${req.originalUrl}. Denying access.`);
        return res.status(401).json({ error: 'Unauthorized', message: 'Authorization header is missing.' });
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
         console.log(`[Auth Middleware] Invalid Authorization header format for ${req.method} ${req.originalUrl}. Expected 'Bearer <token>'.`);
        return res.status(401).json({ error: 'Unauthorized', message: 'Invalid Authorization header format.' });
    }

    const token = parts[1];

    try {
        // Verify the JWT signature and validate claims (like expiration 'exp')
        const decoded = jwt.verify(token, jwtSecret);

        req.user = decoded; // Attach decoded user info
        console.log(`[Auth Middleware] JWT validated for user ID: ${decoded.sub}`);

        // Add user info to request headers for backend services
        // Make sure your backend services are prepared to receive and trust this header
        req.headers['X-User-ID'] = decoded.sub;

        next(); // Proceed to the next middleware/proxy

    } catch (err) {
        console.error(`[Auth Middleware] JWT validation failed for ${req.method} ${req.originalUrl}: ${err.message}`);
        let errorMsg = 'Invalid token';
        if (err.name === 'TokenExpiredError') {
            errorMsg = 'Token expired';
        } else if (err.name === 'JsonWebTokenError') {
             errorMsg = 'Invalid token signature';
        }
        res.status(401).json({ error: 'Unauthorized', message: errorMsg });
    }
};


// --- Define Proxy Routes (Apply middleware here) ---

console.log(`>>> Configuring proxy for /api/users. Target URL: [${userServiceUrl}]`);
// Apply requireAuth middleware BEFORE the proxy if authentication is needed for these routes.
// Based on your latest comment, you removed requireAuth here, so keeping it removed below:
app.use('/api/users',
    // If authentication is required, UNCOMMENT the line below:
    // requireAuth, // <--- UNCOMMENT THIS IF USER/PROPERTY ROUTES NEED AUTH VIA GATEWAY
    createProxyMiddleware({
    target: userServiceUrl,
    changeOrigin: true,
    pathRewrite: {
        '^/api/users': '/profiles', // Example path rewrite
    },
    onProxyReq: (proxyReq, req, res) => {
        console.log(`[Gateway->Users] Proxying request to ${userServiceUrl}${proxyReq.path}`);
        // Authorization and X-User-ID headers will be added by requireAuth *if* it's uncommented above
        console.log(`[Gateway->Users] Authorization Header Sent: ${proxyReq.getHeader('Authorization') ? 'Yes' : 'No'}`);
        console.log(`[Gateway->Users] X-User-ID Header Sent: ${proxyReq.getHeader('X-User-ID') || 'No'}`);

        // ** http-proxy-middleware correctly handles forwarding the raw body
        // ** for POST/PUT etc., as long as no prior middleware has consumed the stream.
        // ** By removing the global body parsers, this works.
    },
    onError: (err, req, res) => {
       console.error('Users Proxy Error:', err);
       if (!res.headersSent) {
           res.status(503).json({ error: 'User service unavailable', details: err.message });
       }
    }
}));


console.log(`>>> Configuring proxy for /api/property-service. Target URL: [${propertiesServiceUrl}]`);
// Apply requireAuth middleware BEFORE the proxy if authentication is needed for these routes.
// Based on your latest comment, you removed requireAuth here, so keeping it removed below:
app.use('/api/property-service',
    // If authentication is required, UNCOMMENT the line below:
    // requireAuth, // <--- UNCOMMENT THIS IF USER/PROPERTY ROUTES NEED AUTH VIA GATEWAY
    createProxyMiddleware({
    target: propertiesServiceUrl,
    changeOrigin: true,
    pathRewrite: {
      '^/api/property-service': '/properties', // Example path rewrite
    },
     onProxyReq: function(proxyReq, req, res) {
        console.log(`[Gateway->Property Service] Proxying ${req.method} request to ${propertiesServiceUrl}${proxyReq.path}`);
        // Authorization and X-User-ID headers will be added by requireAuth *if* it's uncommented above
        console.log(`[Gateway->Property Service] Authorization Header Sent: ${proxyReq.getHeader('Authorization') ? 'Yes' : 'No'}`);
        console.log(`[Gateway->Property Service] X-User-ID Header Sent: ${proxyReq.getHeader('X-User-ID') || 'No'}`);
     },
    onError: (err, req, res) => {
      console.error('Property Service Proxy Error:', err);
      if (!res.headersSent) {
        res.status(503).json({ error: 'Property service unavailable', details: err.message });
      }
    }
  }));


// --- Basic Route for Testing Gateway (No Auth Required by Gateway) ---
app.get('/', (req, res) => {
     res.send('API Gateway is running');
});


// --- Authentication Routes (NEED Body Parsing) ---

// Apply body parsing middleware specifically to the /auth routes
// These routes are handled directly by the Gateway and need to parse request bodies.
// Placing these AFTER the proxy definitions ensures they don't interfere with proxying.
app.use('/auth', express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/auth', express.json());


// 1. Callback URL: Handles the redirect from the OAuth server (GET request, no body parsing needed here)
app.get('/auth/callback', async (req, res) => {
    const { code, error, error_description, state } = req.query;
    console.log('[Gateway /auth/callback] Received callback. Query:', req.query);

    // TODO: Validate the 'state' parameter here

    if (error) {
        console.error('[Gateway /auth/callback] OAuth Error received:', { error, error_description, state });
        const errorRedirectUrl = `${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(error_description || 'Unknown error')}`;
        console.log(`[Gateway /auth/callback] Redirecting to frontend with error: ${errorRedirectUrl}`);
        return res.redirect(errorRedirectUrl);
    }

    if (!code) {
        console.error('[Gateway /auth/callback] OAuth Callback Error: No authorization code received.');
        const errorRedirectUrl = `${process.env.FRONTEND_URL}/login?error=missing_code`;
        console.log(`[Gateway /auth/callback] Redirecting to frontend with error: ${errorRedirectUrl}`);
        return res.redirect(errorRedirectUrl);
    }

    console.log('[Gateway /auth/callback] Extracted code:', code);

    // Prepare payload for token request (data will be URL-encoded by URLSearchParams)
    const tokenPayload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: process.env.GATEWAY_CALLBACK_URI,
        client_id: process.env.OAUTH_CLIENT_ID,
        client_secret: process.env.OAUTH_CLIENT_SECRET
    });

    console.log('[Gateway /auth/callback] Sending request to /token endpoint...');
    try {
        // Exchange authorization code for access token (JWT) and refresh token
        const tokenResponse = await axios.post(`${oauthServerUrl}/token`, tokenPayload, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('[Gateway /auth/callback] Token response received successfully.');

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        if (!access_token) {
            console.error('[Gateway /auth/callback] Token Exchange Error: No access token found in response data.');
            const errorRedirectUrl = `${process.env.FRONTEND_URL}/login?error=token_exchange_failed&error_description=No access token received`;
            console.log(`[Gateway /auth/callback] Redirecting to frontend with error: ${errorRedirectUrl}`);
            return res.redirect(errorRedirectUrl);
        }

        const redirectUrlFragment = new URLSearchParams();
        redirectUrlFragment.set('access_token', access_token);
        if (refresh_token) {
             redirectUrlFragment.set('refresh_token', refresh_token);
        }
        if (expires_in !== undefined) {
            redirectUrlFragment.set('expires_in', expires_in);
        }
        if (state) {
             redirectUrlFragment.set('state', state);
        }

        const finalRedirectUrl = `${process.env.FRONTEND_URL}/auth/callback#${redirectUrlFragment.toString()}`;

        console.log(`[Gateway /auth/callback] Redirecting user to frontend callback with tokens in fragment: ${finalRedirectUrl}`);
        res.redirect(finalRedirectUrl);

    } catch (err) {
        console.error('!!! [Gateway /auth/callback] Error during OAuth token exchange:', err);
        let errorMsg = 'token_exchange_error';
        let errorDesc = 'Failed to exchange authorization code for token.';
         if (err.response) {
            console.error('[Gateway /auth/callback]   -> OAuth Server Error Status:', err.response.status);
             if (err.response.data) console.error('[Gateway /auth/callback]   -> OAuth Server Error Data:', err.response.data);
            errorMsg = err.response.data?.error || errorMsg;
            errorDesc = err.response.data?.error_description || errorDesc;
         } else if (err.request) {
             console.error('[Gateway /auth/callback]   -> No response received from OAuth server:', err.request);
             errorDesc = 'No response received from authentication server.';
         } else {
             console.error('[Gateway /auth/callback]   -> Error setting up token request:', err.message);
             errorDesc = 'Error occurred while preparing authentication request.';
         }
        const errorRedirectUrl = `${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(errorMsg)}&error_description=${encodeURIComponent(errorDesc)}`;
        console.log(`[Gateway /auth/callback] Redirecting to frontend with error: ${errorRedirectUrl}`);
        res.redirect(errorRedirectUrl);
    }
});


// --- Refresh Token Endpoint (Handles POST request with body) ---
app.post('/auth/refresh', async (req, res) => {
    // Body is now parsed by app.use('/auth', express.urlencoded/json) BEFORE this handler runs
    const { refresh_token } = req.body;
    console.log('[Gateway /auth/refresh] Received refresh token request.');
    console.log('[Gateway /auth/refresh] Request body:', req.body); // Log the parsed body

    if (!refresh_token) {
        console.warn('[Gateway /auth/refresh] Missing refresh_token in request body.');
        return res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token is required' });
    }

    const refreshPayload = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refresh_token, // Use the refresh_token from the parsed body
        client_id: process.env.OAUTH_CLIENT_ID,
        client_secret: process.env.OAUTH_CLIENT_SECRET
    });

    console.log('[Gateway /auth/refresh] Sending refresh request to /token endpoint...');
     try {
        const tokenResponse = await axios.post(`${oauthServerUrl}/token`, refreshPayload, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('[Gateway /auth/refresh] Token refresh response received successfully.');

        const { access_token, refresh_token: new_refresh_token, expires_in } = tokenResponse.data;

        if (!access_token) {
             console.error('[Gateway /auth/refresh] Refresh Error: No access token found in response data.');
            return res.status(500).json({ error: 'server_error', error_description: 'OAuth server did not return access token' });
        }

        res.json({
            access_token: access_token,
            refresh_token: new_refresh_token,
            expires_in: expires_in
        });

    } catch (err) {
        console.error('!!! [Gateway /auth/refresh] Error during refresh token exchange:', err);
        let errorMsg = 'refresh_error';
        let errorDesc = 'Failed to refresh access token.';

         if (err.response) {
            console.error('[Gateway /auth/refresh]   -> OAuth Server Error Status:', err.response.status);
             if (err.response.data) console.error('[Gateway /auth/refresh]   -> OAuth Server Error Data:', err.response.data);
            errorMsg = err.response.data?.error || errorMsg;
            errorDesc = err.response.data?.error_description || errorDesc;
            if (err.response.status === 400 && errorMsg === 'invalid_grant') {
                 errorDesc = errorDesc || 'Invalid or expired refresh token. Please log in again.';
                 return res.status(401).json({ error: 'invalid_refresh_token', error_description: errorDesc });
            }
         } else if (err.request) {
             console.error('[Gateway /auth/refresh]   -> No response received from OAuth server:', err.request);
             errorDesc = 'No response received from authentication server during refresh.';
         } else {
             console.error('[Gateway /auth/refresh]   -> Error setting up refresh request:', err.message);
             errorDesc = 'Error occurred while preparing refresh request.';
         }

        res.status(500).json({ error: errorMsg, error_description: errorDesc });
    }
});

// --- Logout Endpoint (Handles POST request with body) ---
app.post('/auth/logout', async (req, res) => {
    // Body is now parsed by app.use('/auth', express.urlencoded/json) before this handler runs
    const { refresh_token } = req.body;
    console.log('[Gateway /auth/logout] Received logout request.');
    console.log('[Gateway /auth/logout] Request body:', req.body); // Log the parsed body


    if (refresh_token) {
        console.log('[Gateway /auth/logout] Attempting to revoke refresh token with OAuth server.');
        // TODO: Implement actual token revocation call to your OAuth server
        /* Example conceptual call (endpoint and parameters vary by OAuth provider):
        try {
             await axios.post(`${oauthServerUrl}/revoke`, new URLSearchParams({
                 token: refresh_token,
                 client_id: process.env.OAUTH_CLIENT_ID,
                 client_secret: process.env.OAUTH_CLIENT_SECRET,
                 token_type_hint: 'refresh_token' // Or 'access_token' if revoking access token
             }), {
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
             });
             console.log('[Gateway /auth/logout] Refresh token revocation successful.');
        } catch (revokeErr) {
             console.error('[Gateway /auth/logout] Error during refresh token revocation:', revokeErr.message);
        }
        */
    } else {
        console.log('[Gateway /auth/logout] No refresh token provided for revocation.');
    }

    res.status(200).json({ message: 'Logout request processed (frontend should clear tokens).' });
});


// --- 404 Handler for unmatched routes on the gateway ---
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found on Gateway' });
});

// --- Start the Gateway Server ---
module.exports = app;

// Start the server only if the file is executed directly (not when imported for testing)
if (require.main === module) { 
  app.listen(gatewayPort, () => {
    console.log(`API Gateway listening at http://localhost:${gatewayPort}`);
    console.log(`Frontend URL configured as: ${process.env.FRONTEND_URL}`);
    console.log(`OAuth Server URL configured as: ${process.env.OAUTH_SERVER_URL}`);
    console.log(`OAuth Callback URI configured as: ${process.env.GATEWAY_CALLBACK_URI}`);
    console.log(`JWT Secret loaded: ${jwtSecret ? 'Yes' : 'No (FATAL!)'}`);
    // NOTE: These routes no longer require auth *at the Gateway level* in this config
    console.log(`Proxying /api/users -> ${userServiceUrl}/profiles (NO AUTH REQUIRED AT GATEWAY)`);
    console.log(`Proxying /api/property-service -> ${propertiesServiceUrl}/properties (NO AUTH REQUIRED AT GATEWAY)`);
  });
}