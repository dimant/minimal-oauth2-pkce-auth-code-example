using AuthServer;

// using to bind form data in POST requests by using [FromForm] attribute
using Microsoft.AspNetCore.Mvc;

var _tenants = new Dictionary<string, Tenant>();
/// Initialize a sample tenant with some data
var tenant = new Tenant("tenant1");
_tenants.Add(tenant.GetId(), tenant);

tenant.AppRegistrations.Register(new AppInfo
{
    ClientId = "app1",
    RedirectUri = "http://localhost:5002/#/callback",
    Scopes = new[] { "read", "write" }
});

tenant.UserRegistrations.Register(new UserInfo
{
    Username = "user1",
    Password = "password1"
});

tenant.UserRegistrations.Register(new UserInfo
{
    Username = "user2",
    Password = "password2"
});

tenant.UserGrants.Register(new UserGrants
{
    Username = "user1",
    Grants = new List<(string ClientId, string Scope)>
    {
        ("app1", "read"),
        ("app1", "write")
    }
});

tenant.UserGrants.Register(new UserGrants
{
    Username = "user2",
    Grants = new List<(string ClientId, string Scope)>
    {
        ("app1", "read")
    }
});

var _authorizationCodeHandler = new AuthorizationCodeHandler();

// This is the core of an auth server - signing certificates and JWT handler
// In this example we generate a self-signed certificate for signing tokens.
// In a production system, you would obtain a certificate from a trusted
// Certificate Authority (CA) or use a managed certificate service.
// In a production system, you would also treat the certificate as a mission
// critical secret and store it securely (e.g., in Key Vault). If it is leaked,
// attackers could forge valid tokens and access any resource that trusts
// tokens from this auth server.
// In this implementation we have a seprate certificate per tenant.
var _jwtHandler = new JwtHandler(
    issuer: "http://localhost:5000",
    privateKeyBase64: tenant.SigningCertificateHandler.GetPrivateKey());
int expirationSeconds = 3600;

var builder = WebApplication.CreateBuilder(args);

// Add CORS policy to allow requests from the web client
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowWebClient", policy =>
    {
        policy.WithOrigins("http://localhost:5002")
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Use CORS middleware
app.UseCors("AllowWebClient");

// OAuth2 Authorization Endpoint
// tenantId is part of the path
// Example: /tenant1/oauth2/v2.0/authorize?client_id=app1&redirect_uri=http://localhost:5002/callback&scope=read
// The endpoint serves a simple login form
// On successful login, it redirects to the redirect_uri with an authorization code
app.MapGet("/{tenantId}/oauth2/v2.0/authorize", (
    string tenantId,
    string client_id,
    string redirect_uri,
    string scope,
    string code_challenge,
    string code_challenge_method) =>
{
    // Confirm tenant exists
    Tenant? tenant;
    if (tenantId == null || !_tenants.TryGetValue(tenantId, out tenant))
    {
        return Results.NotFound("Tenant not found");
    }

    if (string.IsNullOrEmpty(client_id) ||
        string.IsNullOrEmpty(redirect_uri) ||
        string.IsNullOrEmpty(scope) ||
        string.IsNullOrEmpty(code_challenge) ||
        string.IsNullOrEmpty(code_challenge_method))
    {
        return Results.BadRequest("Missing required parameters");
    }

    // Confirm client_id is registered
    AppInfo? appInfo = tenant.AppRegistrations.Get(client_id);
    if (appInfo == null)
    {
        return Results.BadRequest("Invalid client_id");
    }

    // Confirm redirect_uri matches registered value
    // In a real implementation we would verify the scheme, host, port, path, etc.
    // In particular we would want to verify that the tenant actually owns the
    // domain named in the redirect_uri
    if (appInfo.RedirectUri != redirect_uri)
    {
        return Results.BadRequest("Invalid redirect_uri");
    }

    // Confirm requested scopes are valid for the application.
    // In this simple implementation we are omitting scope consent. We assume
    // that if the requested scopes are valid for the application, they are granted.
    // In a real implementation consent may be granted by the tenant admin for the
    // application, but also individual users may be able to consent to scopes.
    // Consenting means to allow the client application to access resources on behalf
    // of the user. That way, if I am using a third-party app, I can choose to allow it
    // to read my data from the resource server. For example, a photo printing app may
    // want to read my photos from a photo storage service.
    var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var invalidScopes = requestedScopes.Except(appInfo.Scopes).ToList();

    if (invalidScopes.Count > 0)
    {
        return Results.BadRequest($"Invalid scopes for client_id '{client_id}': {string.Join(", ", invalidScopes)}");
    }

    // Serve simple login form
    var html = $@"
        <html>
        <body>
            <h1>Login</h1>
            <form method='post' action='/{tenantId}/oauth2/v2.0/authorize/login'>
                <input type='hidden' name='client_id' value='{client_id}' />
                <input type='hidden' name='redirect_uri' value='{redirect_uri}' />
                <input type='hidden' name='scope' value='{scope}' />
                <input type='hidden' name='code_challenge' value='{code_challenge}' />
                <input type='hidden' name='code_challenge_method' value='{code_challenge_method}' />
                <input type='text' name='username' placeholder='Username' required />
                <input type='password' name='password' placeholder='Password' required />
                <button type='submit'>Login</button>
            </form>
        </body>
        </html>";
    return Results.Content(html, "text/html");
});

// OAuth2 Authorization Endpoint - Login POST handler
// Once the user submits the login form, this endpoint validates the credentials
// and redirects to the redirect_uri with an authorization code if successful.
app.MapPost("/{tenantId}/oauth2/v2.0/authorize/login", (
    string tenantId,
    [FromForm] string username,
    [FromForm] string password,
    [FromForm] string client_id,
    [FromForm] string redirect_uri,
    [FromForm] string scope,
    [FromForm] string code_challenge,
    [FromForm] string code_challenge_method) =>
{
    var user = tenant.UserRegistrations.Get(username);
    if (user?.Password == password)
    {
        var authorizationCode = _authorizationCodeHandler.GenerateCode(
            tenantId,
            client_id,
            username,
            scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(),
            codeChallenge: code_challenge,
            codeChallengeMethod: code_challenge_method);
        return Results.Redirect($"{redirect_uri}?code={authorizationCode}");
    }
    return Results.Content("<h1>Invalid credentials</h1>", "text/html");
}).DisableAntiforgery(); // Disable antiforgery for simplicity in this example. In production we want to be certain that the login form was served by us and not a phishing site.

// OAuth2 Token Endpoint
// The client exchanges the authorization code for an access token
app.MapPost("/{tenantId}/oauth2/v2.0/token", (
    string tenantId,
    [FromForm] string grant_type,
    [FromForm] string code,
    [FromForm] string redirect_uri,
    [FromForm] string client_id,
    [FromForm] string code_verifier) =>
{
    if (grant_type != "authorization_code")
    {
        return Results.BadRequest(new { error = "unsupported_grant_type" });
    }

    var authCodeRecord = _authorizationCodeHandler.ValidateCode(code, code_verifier);
    if (authCodeRecord == null)
    {
        return Results.BadRequest(new { error = "invalid_code" });
    }

    if (authCodeRecord.ClientId != client_id)
    {
        return Results.BadRequest(new { error = "invalid_client" });
    }

    var tenant = _tenants[tenantId];
    var appInfo = tenant.AppRegistrations.Get(client_id);
    if (appInfo == null || appInfo.RedirectUri != redirect_uri)
    {
        return Results.BadRequest(new { error = "invalid_request" });
    }

    // Generate an access token using JWT
    var accessToken = _jwtHandler.GenerateAccessToken(
        tenantId,
        client_id,
        authCodeRecord.Username,
        authCodeRecord.Scopes,
        expirationSeconds);

    var response = new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = expirationSeconds,
        scope = string.Join(" ", authCodeRecord.Scopes)
    };

    return Results.Json(response);
}).DisableAntiforgery();

// Public Key Endpoint
// Returns the public key used to verify tokens
// This is typically used by resource servers to validate access tokens
app.MapGet("/{tenantId}/oauth2/v2.0/public-key", (string tenantId) =>
{
    // Confirm tenant exists
    Tenant? tenant;
    if (tenantId == null || !_tenants.TryGetValue(tenantId, out tenant))
    {
        return Results.NotFound("Tenant not found");
    }

    var publicKey = tenant.SigningCertificateHandler.GetPublicKey();
    
    var response = new
    {
        public_key = publicKey,
        key_type = "RSA",
        algorithm = "RS256"
    };

    return Results.Json(response);
});

app.Run("http://localhost:5000");
