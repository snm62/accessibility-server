// Complete Accessibility Widget Cloudflare Worker
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleCORS();
    }
    
    // OAuth Authorization - redirect to Webflow
    if (url.pathname === '/api/auth/authorize') {
      return handleOAuthAuthorize(request, env);
    }
    
    // OAuth Callback - handle Webflow redirect
    if (url.pathname === '/api/auth/callback') {
      return handleOAuthCallback(request, env);
    }
    
    // Token Authentication
    if (url.pathname === '/api/auth/token' && request.method === 'POST') {
      return handleTokenAuth(request, env);
    }
    
    // Get accessibility settings
    if (url.pathname === '/api/accessibility/settings' && request.method === 'GET') {
      return handleGetSettings(request, env);
    }
    
    // Update accessibility settings
    if (url.pathname === '/api/accessibility/settings' && (request.method === 'POST' || request.method === 'PUT')) {
      return handleUpdateSettings(request, env);
    }
    
    // Verify authentication
    if (url.pathname === '/api/auth/verify') {
      return handleVerifyAuth(request, env);
    }
    
    // Default response
    return new Response('Accessibility Widget API', { 
      status: 200,
      headers: { 
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
};

// Handle CORS preflight requests
function handleCORS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    }
  });
}

// Handle OAuth Authorization - FIXED TO REMOVE DUPLICATE DECLARATION
async function handleOAuthAuthorize(request, env) {
  const url = new URL(request.url);
  const incomingState = url.searchParams.get("state");
  const siteId = url.searchParams.get("siteId");
  
  // Determine flow type and extract site ID
  const isDesigner = incomingState && incomingState.startsWith("webflow_designer");
  
  const scopes = [
    "sites:read",
    "sites:write", 
    "custom_code:read",
    "custom_code:write",
    "authorized_user:read"
  ];
  
  // Use your worker's redirect URI for both flows
  const redirectUri = "https://accessibility-widget.web-8fb.workers.dev/api/auth/callback";
  
  const authUrl = new URL('https://webflow.com/oauth/authorize');
  authUrl.searchParams.set('client_id', env.WEBFLOW_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', scopes.join(' '));
  
  // Set state parameter with site ID for App Interface
  if (isDesigner) {
    const currentSiteId = siteId || (incomingState.includes('_') ? incomingState.split('_')[1] : null);
    if (currentSiteId) {
      authUrl.searchParams.set('state', `webflow_designer_${currentSiteId}`);
    } else {
      authUrl.searchParams.set('state', 'webflow_designer');
    }
  } else {
    authUrl.searchParams.set('state', 'accessibility_widget');
  }
  
  return new Response(null, {
    status: 302,
    headers: {
      'Location': authUrl.toString()
    }
  });
}

// Handle OAuth Callback - FIXED TO HANDLE BOTH FLOWS CORRECTLY
async function handleOAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  if (!code) {
    return new Response(JSON.stringify({ error: 'No authorization code provided' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
// Handle missing state parameter - assume Apps & Integrations flow
if (!state) {
  // Continue with Apps & Integrations flow instead of throwing error
}
  try {
    const isDesigner = state && state.startsWith('webflow_designer');
    const redirectUri = "https://accessibility-widget.web-8fb.workers.dev/api/auth/callback";
    
    console.log('=== OAUTH CALLBACK DEBUG ===');
    console.log('Request URL:', request.url);
    console.log('Code received:', code);
    console.log('State:', state);
    console.log('Using redirect URI:', redirectUri);
    console.log('Client ID:', env.WEBFLOW_CLIENT_ID);
    console.log('Flow type:', isDesigner ? 'App Interface' : 'Apps & Integrations');
    
    // Build token exchange request body conditionally
    const tokenRequestBody = {
      client_id: env.WEBFLOW_CLIENT_ID,
      client_secret: env.WEBFLOW_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code'
    };
    
    // Only include redirect_uri for App Interface flow
    if (isDesigner) {
      tokenRequestBody.redirect_uri = redirectUri;
    }
    
    console.log('Token request body:', JSON.stringify(tokenRequestBody, null, 2));
    
    const tokenResponse = await fetch('https://api.webflow.com/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(tokenRequestBody)
    });
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', tokenResponse.status, errorText);
      throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errorText}`);
    }
    
    const tokenData = await tokenResponse.json();
    console.log('Token exchange successful');
    
    // Get user info
    const userResponse = await fetch('https://api.webflow.com/v2/token/authorized_by', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'accept-version': '2.0.0'
      }
    });
    
    if (!userResponse.ok) {
      throw new Error(`User fetch failed: ${userResponse.status}`);
    }
    
    const userData = await userResponse.json();
    
    // Get sites
    const sitesResponse = await fetch('https://api.webflow.com/v2/sites', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'accept-version': '2.0.0'
      }
    });
    
    if (!sitesResponse.ok) {
      throw new Error(`Sites fetch failed: ${sitesResponse.status}`);
    }
    
    const sitesData = await sitesResponse.json();
    let sites = [];
    if (sitesData.sites) {
      sites = sitesData.sites;
    } else if (sitesData.items) {
      sites = sitesData.items;
    } else if (Array.isArray(sitesData)) {
      sites = sitesData;
    }
    
    if (sites.length === 0) {
      throw new Error('No Webflow sites found');
    }
    
    // Generate JWT session token FIRST
    const sessionToken = await createSessionToken(userData, env);
    
    // Handle different redirect scenarios
    if (isDesigner) {
      // App Interface flow - only store data for the current site
      const siteIdFromState = state.includes('_') ? state.split('_')[1] : null;
      
      // Find the specific site or use the first one
      let currentSite;
      if (siteIdFromState) {
        currentSite = sites.find(site => site.id === siteIdFromState) || sites[0];
      } else {
        currentSite = sites[0];
      }
      
      // Store data only for the current site
      await env.ACCESSIBILITY_AUTH.put(currentSite.id, JSON.stringify({
        accessToken: tokenData.access_token,
        siteName: currentSite.shortName,
        siteId: currentSite.id,
        user: userData,
        installedAt: new Date().toISOString(),
        accessibilitySettings: {
          fontSize: 'medium',
          contrast: 'normal',
          animations: true,
          screenReader: false,
          keyboardNavigation: true,
          focusIndicators: true,
          highContrast: false,
          reducedMotion: false,
          textSpacing: 'normal',
          cursorSize: 'normal'
        },
        widgetVersion: '1.0.0',
        lastUsed: new Date().toISOString()
      }), { expirationTtl: 86400 });
      
      // App Interface flow - send data to parent window
      return new Response(`<!DOCTYPE html>
        <html>
          <head>
            <title>Accessibility Widget Installed</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              .success { color: #28a745; }
            </style>
          </head>
          <body>
            <h1 class="success">✅ Accessibility Widget Installed Successfully!</h1>
            <p>Your accessibility widget is now active on this site.</p>
            <script>
              const sessionData = {
                type: 'AUTH_SUCCESS',
                sessionToken: '${sessionToken.token}',
                user: {
                  firstName: '${userData.firstName || 'User'}',
                  email: '${userData.email}',
                  siteId: '${currentSite.id}'
                },
                siteInfo: {
                  siteId: '${currentSite.id}',
                  siteName: '${currentSite.name}',
                  shortName: '${currentSite.shortName}',
                  url: '${currentSite.url}'
                }
              };
              
              window.opener.postMessage(sessionData, '*');
              window.close();
            </script>
          </body>
        </html>`, {
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    // Apps & Integrations flow - store data for all sites
    const storePromises = sites.map(site => 
      env.ACCESSIBILITY_AUTH.put(site.id, JSON.stringify({
        accessToken: tokenData.access_token,
        siteName: site.shortName,
        siteId: site.id,
        user: userData,
        installedAt: new Date().toISOString(),
        accessibilitySettings: {
          fontSize: 'medium',
          contrast: 'normal',
          animations: true,
          screenReader: false,
          keyboardNavigation: true,
          focusIndicators: true,
          highContrast: false,
          reducedMotion: false,
          textSpacing: 'normal',
          cursorSize: 'normal'
        },
        widgetVersion: '1.0.0',
        lastUsed: new Date().toISOString()
      }), { expirationTtl: 86400 })
    );
    
    await Promise.all(storePromises);
    
    // Apps & Integrations flow - redirect to site with success message
    const firstSite = sites[0];
    return new Response(`<!DOCTYPE html>
      <html>
        <head>
          <title>Accessibility Widget Installed</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .success { color: #28a745; }
            .redirect { color: #007bff; margin-top: 20px; }
          </style>
        </head>
        <body>
          <h1 class="success">✅Accessibility Widget Installed Successfully!</h1>
          <p>Your accessibility widget is now active on this site.</p>
          <p class="redirect">Redirecting to your site...</p>
          <script>
            // Store site info in session storage
            sessionStorage.setItem('wf_hybrid_user', JSON.stringify({
              sessionToken: '${sessionToken.token}',
              firstName: '${userData.firstName || 'User'}',
              email: '${userData.email}',
              exp: Date.now() + (24 * 60 * 60 * 1000),
              siteInfo: {
                siteId: '${firstSite.id}',
                siteName: '${firstSite.name}',
                shortName: '${firstSite.shortName}',
                url: '${firstSite.url}'
              }
            }));
            
            // Redirect to the site after a short delay
            setTimeout(() => {
              window.location.href = 'https://${firstSite.shortName}.design.webflow.com?app=${env.WEBFLOW_CLIENT_ID}';
            }, 2000);
          </script>
        </body>
      </html>`, {
      headers: { 'Content-Type': 'text/html' }
    });
    
  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(JSON.stringify({ 
      error: 'Authorization failed', 
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Handle Token Authentication - UPDATED TO V2 WITH CORS
async function handleTokenAuth(request, env) {
  try {
    console.log('=== TOKEN AUTH DEBUG START ===');
    console.log('Request method:', request.method);
    console.log('Request URL:', request.url);
    console.log('Request headers:', Object.fromEntries(request.headers.entries()));
    
    const { siteId, idToken } = await request.json();
    console.log('Parsed request body:', { siteId: !!siteId, idToken: !!idToken });
    
    if (!siteId || !idToken) {
      console.error('Missing required parameters');
      return new Response(JSON.stringify({ error: 'Missing siteId or idToken' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    // Get access token for this site
    console.log('Looking up site data for siteId:', siteId);
    const siteData = await env.ACCESSIBILITY_AUTH.get(siteId);
    if (!siteData) {
      console.error('Site not found in KV store');
      return new Response(JSON.stringify({ error: 'Site not found or not authorized' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    const { accessToken } = JSON.parse(siteData);
    console.log('Found access token for site');
    
    // Verify user with Webflow - UPDATED TO V2
    console.log('Verifying user with Webflow...');
    const resolveResponse = await fetch('https://api.webflow.com/v2/token/resolve', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
        'accept-version': '2.0.0'
      },
      body: JSON.stringify({ idToken })
    });
    
    console.log('Webflow resolve response status:', resolveResponse.status);
    
    if (!resolveResponse.ok) {
      const errorText = await resolveResponse.text();
      console.error('Token resolve failed:', resolveResponse.status, errorText);
      return new Response(JSON.stringify({ error: 'Failed to verify user' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    const userData = await resolveResponse.json();
    console.log('Resolved user data:', JSON.stringify(userData, null, 2));
    
    if (!userData.id || !userData.email) {
      console.error('Invalid user data received');
      return new Response(JSON.stringify({ error: 'Invalid user data received' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    // Create session token
    console.log('Creating session token...');
    const sessionToken = await createSessionToken(userData, env);
    console.log('Session token created successfully');
    
    // Store user authentication
    await env.ACCESSIBILITY_AUTH.put(`user-auth:${userData.id}`, JSON.stringify({
      accessToken,
      userData: {
        id: userData.id,
        email: userData.email,
        firstName: userData.firstName
      },
      siteId,
      widgetType: 'accessibility'
    }), { expirationTtl: 86400 });
    
    console.log('User authentication stored');
    console.log('=== TOKEN AUTH DEBUG END ===');
    
    return new Response(JSON.stringify({
      sessionToken: sessionToken.token,
      email: userData.email,
      firstName: userData.firstName,
      exp: sessionToken.exp,
      widgetType: 'accessibility'
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
    
  } catch (error) {
    console.error('Token auth error:', error);
    return new Response(JSON.stringify({ 
      error: 'Authentication failed',
      details: error.message 
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
}

// Get accessibility settings
async function handleGetSettings(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
  
  const { siteId } = authResult;
  const siteData = await env.ACCESSIBILITY_AUTH.get(siteId);
  
  if (!siteData) {
    return new Response(JSON.stringify({ error: 'Site not found' }), {
      status: 404,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
  
  const { accessibilitySettings, siteName, installedAt, lastUsed, widgetVersion } = JSON.parse(siteData);
  
  return new Response(JSON.stringify({
    settings: accessibilitySettings,
    siteId: siteId,
    siteName: siteName,
    installedAt: installedAt,
    lastUsed: lastUsed,
    widgetVersion: widgetVersion
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

// Update accessibility settings
async function handleUpdateSettings(request, env) {
  const authResult = await verifyAuth(request, env);
  if (!authResult) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, PUT, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
  
  const { siteId } = authResult;
  const newSettings = await request.json();
  
  const siteData = await env.ACCESSIBILITY_AUTH.get(siteId);
  if (!siteData) {
    return new Response(JSON.stringify({ error: 'Site not found' }), {
      status: 404,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, PUT, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
  
  const siteInfo = JSON.parse(siteData);
  siteInfo.accessibilitySettings = { ...siteInfo.accessibilitySettings, ...newSettings };
  siteInfo.lastUpdated = new Date().toISOString();
  siteInfo.lastUsed = new Date().toISOString();
  
  await env.ACCESSIBILITY_AUTH.put(siteId, JSON.stringify(siteInfo), { expirationTtl: 86400 });
  
  return new Response(JSON.stringify({
    success: true,
    settings: siteInfo.accessibilitySettings,
    lastUpdated: siteInfo.lastUpdated
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

// Verify authentication
async function handleVerifyAuth(request, env) {
  const authResult = await verifyAuth(request, env);
  
  return new Response(JSON.stringify({
    authenticated: !!authResult,
    user: authResult?.userData || null
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

// Helper function to verify authentication
async function verifyAuth(request, env) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader) return null;
  
  const token = authHeader.split(' ')[1];
  if (!token) return null;
  
  try {
    // Verify JWT token
    const payload = await verifyJWT(token, env.WEBFLOW_CLIENT_SECRET);
    const userId = payload.user.id;
    
    // Get user data from KV
    const userData = await env.ACCESSIBILITY_AUTH.get(`user-auth:${userId}`);
    if (!userData) return null;
    
    const { accessToken, userData: user, siteId } = JSON.parse(userData);
    
    return {
      accessToken,
      userData: user,
      siteId
    };
  } catch (error) {
    console.error('Auth verification error:', error);
    return null;
  }
}
// Create JWT session token
async function createSessionToken(user, env) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const payload = {
    user: user,
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
  };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  const signature = await signJWT(
    `${encodedHeader}.${encodedPayload}`,
    env.WEBFLOW_CLIENT_SECRET
  );
  
  return {
    token: `${encodedHeader}.${encodedPayload}.${signature}`,
    exp: payload.exp
  };
}
// Create JWT session token

// Verify JWT token
async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');
  
  const [header, payload, signature] = parts;
  
  // Verify signature
  const expectedSignature = await signJWT(`${header}.${payload}`, secret);
  if (signature !== expectedSignature) {
    throw new Error('Invalid signature');
  }
  
  // Check expiration
  const decodedPayload = JSON.parse(base64UrlDecode(payload));
  if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }
  
  return decodedPayload;
}

// Sign JWT
async function signJWT(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64UrlEncode(new Uint8Array(signature));
}

// Base64 URL encoding helpers
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  str += '='.repeat((4 - str.length % 4) % 4);
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  return atob(str);
}
