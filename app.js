require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
// const session = require('express-session'); // <<< REMOVE session middleware
const axios = require('axios');
const jwt = require('jsonwebtoken');

const app = express();
const gatewayPort = process.env.GATEWAY_PORT || 3002;

// --- Configuration Validation ---
const requiredEnvVars = [
    'PROPERTIES_SERVICE_URL',
    'OAUTH_SERVER_URL',
    'OAUTH_CLIENT_ID',
    'OAUTH_CLIENT_SECRET',
    'GATEWAY_CALLBACK_URI',
    // 'SESSION_SECRET', // <<< REMOVE SESSION_SECRET validation
    'FRONTEND_URL', // Needed for redirects
    'JWT_SECRET' // <<< ADD JWT_SECRET validation
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
// This MUST match the secret key used by your OAuth Server to sign JWTs
const jwtSecret = process.env.JWT_SECRET;

// --- Middleware ---

// CORS Configuration: No longer need `credentials: true` if not using cookies/sessions for auth
// Restrict origin to your frontend URL
app.use(cors({
    origin: process.env.FRONTEND_URL,
    // credentials: true // <<< REMOVE or reconsider if other cookies are used
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- REMOVE Session Configuration ---
/*
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));
*/

// --- Authentication Middleware for Protected Routes (JWT Validation) ---
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

        // Attach decoded user info to the request object for downstream services/logging
        // The 'sub' claim is typically the user ID
        req.user = decoded;
        console.log(`[Auth Middleware] JWT validated for user ID: ${decoded.sub}`);

        // Optionally add user info to request headers for backend services
        // Make sure your backend services are prepared to receive and trust this header
        req.headers['X-User-ID'] = decoded.sub;
        // You could also add other claims like roles if present in the JWT
        // if (decoded.roles) {
        //     req.headers['X-User-Roles'] = JSON.stringify(decoded.roles);
        // }

        // Proceed to the next middleware or proxy
        next();

    } catch (err) {
        // Handle various JWT validation errors (e.g., expired, invalid signature)
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


console.log(`>>> Configuring proxy for /api/users. Target URL: [${userServiceUrl}]`);

// *** ADD USER PROXY ROUTE ***
// Add requireAuth middleware before createProxyMiddleware
app.use('/api/users', requireAuth, createProxyMiddleware({
    target: userServiceUrl,
    changeOrigin: true,
    pathRewrite: {
        '^/api/users': '/profiles', // Example path rewrite
    },
    onProxyReq: (proxyReq, req, res) => {
        // The Authorization header (and X-User-ID, etc.) is already added by requireAuth middleware
        console.log(`[Gateway->Users] Proxying request to ${userServiceUrl}${proxyReq.path}`);
         console.log(`[Gateway->Users] Authorization Header Sent: ${proxyReq.getHeader('Authorization') ? 'Yes' : 'No'}`);
         console.log(`[Gateway->Users] X-User-ID Header Sent: ${proxyReq.getHeader('X-User-ID') || 'No'}`);

         // If you had body parsing middleware before the proxy, you might need
         // to manually write the body to proxyReq here if the body was consumed.
         // Since we removed the general json() middleware before proxies,
         // the default behavior of http-proxy-middleware should forward the raw body.
    },
    onError: (err, req, res) => {
       console.error('Users Proxy Error:', err);
       if (!res.headersSent) {
           res.status(503).json({ error: 'User service unavailable', details: err.message });
       }
    }
}));


// Use the new path prefix '/api/property-service'
// Add body parsing explicitly AFTER the proxy check if needed for non-proxy routes
// app.use(express.json()); // Removed general json parsing
// app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Removed general urlencoded parsing


// --- ADD JSON body parsing for specific routes if needed BEFORE proxy ---
// For proxy routes like '/api/property-service', http-proxy-middleware
// handles forwarding the raw request body by default, which is usually correct.
// If you need to inspect/modify the body *before* proxying, you'd add
// body parsing middleware here and then manually write the body in onProxyReq.
// Let's keep it simple and rely on default proxy behavior for now.


app.use('/api/property-service', requireAuth, createProxyMiddleware({ // Add requireAuth
    target: propertiesServiceUrl,
    changeOrigin: true,
    pathRewrite: {
      '^/api/property-service': '/properties', // Example path rewrite
    },
    onProxyReq: function(proxyReq, req, res) {
      // The Authorization header (and X-User-ID, etc.) is already added by requireAuth middleware
      console.log(`[Gateway->Property Service] Proxying ${req.method} request to ${propertiesServiceUrl}${proxyReq.path}`);
      console.log(`[Gateway->Property Service] Authorization Header Sent: ${proxyReq.getHeader('Authorization') ? 'Yes' : 'No'}`);
      console.log(`[Gateway->Property Service] X-User-ID Header Sent: ${proxyReq.getHeader('X-User-ID') || 'No'}`);
       // No need to manually write body here if relying on default proxy behavior
    },
    onError: (err, req, res) => {
      console.error('Property Service Proxy Error:', err);
      if (!res.headersSent) {
        res.status(503).json({ error: 'Property service unavailable', details: err.message });
      }
    }
  }));

// --- Basic Route for Testing Gateway (Optional Authentication) ---
// You could add requireAuth here if even the root needs authentication
app.get('/', (req, res) => {
     // Example of accessing user info if requireAuth was used on '/'
     // if (req.user) {
     //     res.send(`API Gateway is running. Authenticated as user ${req.user.sub}.`);
     // } else {
     //     res.send('API Gateway is running (unauthenticated).');
     // }
     res.send('API Gateway is running');
});


// --- Authentication Routes ---

// 1. Callback URL: Handles the redirect from the OAuth server
// It receives the authorization 'code' and exchanges it for tokens,
// then redirects to the frontend with tokens in the URL fragment.
app.get('/auth/callback', async (req, res) => {
    const { code, error, error_description, state } = req.query; // Added state
    console.log('[Gateway /auth/callback] Received callback. Query:', req.query);

    // TODO: Validate the 'state' parameter here against the state stored in the frontend
    // (e.g., in localStorage) before initiating the /token exchange. This prevents CSRF.
    // The frontend should have generated and sent a 'state' parameter in the initial
    // /authorize request and stored it.

    if (error) {
        console.error('[Gateway /auth/callback] OAuth Error received:', { error, error_description, state });
        // Redirect to frontend with error information in query parameters
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

    // Prepare payload for token request
    const tokenPayload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: process.env.GATEWAY_CALLBACK_URI, // Must match exactly
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
        console.log('[Gateway /auth/callback]   -> Status:', tokenResponse.status);
        // WARNING: Avoid logging the full token data in production logs
        // console.log('[Gateway /auth/callback]   -> Data:', tokenResponse.data);

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        if (!access_token) {
            console.error('[Gateway /auth/callback] Token Exchange Error: No access token found in response data.');
            const errorRedirectUrl = `${process.env.FRONTEND_URL}/login?error=token_exchange_failed&error_description=No access token received`;
            console.log(`[Gateway /auth/callback] Redirecting to frontend with error: ${errorRedirectUrl}`);
             return res.redirect(errorRedirectUrl);
        }

        // 3. Redirect user back to the frontend dashboard with tokens in URL Fragment
        // Construct the redirect URL with the access token, refresh token, and expires_in in the fragment
        // The frontend will parse this fragment upon arrival
        const redirectUrlFragment = new URLSearchParams();
        redirectUrlFragment.set('access_token', access_token);
        if (refresh_token) { // Include refresh token if provided
             redirectUrlFragment.set('refresh_token', refresh_token);
        }
        if (expires_in !== undefined) { // Include expires_in if provided
            redirectUrlFragment.set('expires_in', expires_in);
        }
        if (state) { // Pass state back to frontend for validation if needed there
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
             // Log response body if it exists and is not too large/sensitive
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

        // Redirect to frontend with specific error info
        const errorRedirectUrl = `${process.env.FRONTEND_URL}/login?error=${encodeURIComponent(errorMsg)}&error_description=${encodeURIComponent(errorDesc)}`;
        console.log(`[Gateway /auth/callback] Redirecting to frontend with error: ${errorRedirectUrl}`);
        res.redirect(errorRedirectUrl);
    }
});

// --- NEW: Refresh Token Endpoint ---
// This endpoint is called by the frontend when the access token is about to expire or is expired.
app.post('/auth/refresh', async (req, res) => {
    const { refresh_token } = req.body;
    console.log('[Gateway /auth/refresh] Received refresh token request.');

    if (!refresh_token) {
        console.warn('[Gateway /auth/refresh] Missing refresh_token in request body.');
        return res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token is required' });
    }

    // Prepare payload for refresh token request to the OAuth server
    const refreshPayload = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        client_id: process.env.OAUTH_CLIENT_ID,
        client_secret: process.env.OAUTH_CLIENT_SECRET // Refresh token requests also require client authentication
    });

    console.log('[Gateway /auth/refresh] Sending refresh request to /token endpoint...');
     try {
        // Send refresh token request to the OAuth server's /token endpoint
        const tokenResponse = await axios.post(`${oauthServerUrl}/token`, refreshPayload, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('[Gateway /auth/refresh] Token refresh response received successfully.');
        console.log('[Gateway /auth/refresh]   -> Status:', tokenResponse.status);
        // WARNING: Avoid logging the full token data
        // console.log('[Gateway /auth/refresh]   -> Data:', tokenResponse.data);

        const { access_token, refresh_token: new_refresh_token, expires_in } = tokenResponse.data;

        if (!access_token) {
             console.error('[Gateway /auth/refresh] Refresh Error: No access token found in response data.');
            return res.status(500).json({ error: 'server_error', error_description: 'OAuth server did not return access token' });
        }

        // Return the new tokens to the frontend
        res.json({
            access_token: access_token,
            refresh_token: new_refresh_token, // May be a new refresh token (rotation) or the same one
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
                 // If the refresh token is invalid or expired according to the OAuth server
                 errorDesc = errorDesc || 'Invalid or expired refresh token. Please log in again.';
                 // Consider sending a specific error code/message to the frontend
                 // so it knows to prompt the user for a full re-login.
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

// --- Logout Endpoint (Optional - can just be client-side clearing storage) ---
// If your OAuth server supports refresh token revocation, you could call it here.
// Otherwise, this endpoint doesn't do much server-side without sessions.
app.post('/auth/logout', async (req, res) => {
    // In a non-session flow, the main "logout" action is the frontend clearing its tokens.
    // If your OAuth server has a token revocation endpoint, you can call it here
    // using the refresh_token sent by the frontend in the request body (requires POST).
    const { refresh_token } = req.body;
    console.log('[Gateway /auth/logout] Received logout request.');

    if (refresh_token) {
        console.log('[Gateway /auth/logout] Attempting to revoke refresh token with OAuth server.');
        // TODO: Implement actual token revocation call to your OAuth server
        // Example conceptual call (endpoint and parameters vary by OAuth provider):
        /*
        try {
             await axios.post(`${oauthServerUrl}/revoke`, new URLSearchParams({
                 token: refresh_token,
                 client_id: process.env.OAUTH_CLIENT_ID,
                 client_secret: process.env.OAUTH_CLIENT_SECRET,
                 token_type_hint: 'refresh_token'
             }), {
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
             });
             console.log('[Gateway /auth/logout] Refresh token revocation successful.');
        } catch (revokeErr) {
             console.error('[Gateway /auth/logout] Error during refresh token revocation:', revokeErr.message);
             // Decide how to handle revocation errors - might not need to fail the logout process
        }
        */
    } else {
        console.log('[Gateway /auth/logout] No refresh token provided for revocation.');
    }

    // Since there's no session to destroy on the gateway side for auth state,
    // we just send a success response. The frontend is responsible for
    // clearing its stored tokens (localStorage, etc.).
    res.status(200).json({ message: 'Logout request processed (frontend should clear tokens).' });

    // If redirecting after logout is preferred:
    // res.redirect(`${process.env.FRONTEND_URL}/login?logout=success`);
});


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
    console.log(`JWT Secret loaded: ${jwtSecret ? 'Yes' : 'No (FATAL!)'}`); // Check secret loading
    console.log(`Proxying /api/users -> ${userServiceUrl}/profiles (Authentication Required)`); // Corrected log
    console.log(`Proxying /api/property-service -> ${propertiesServiceUrl}/properties (Authentication Required)`);
});