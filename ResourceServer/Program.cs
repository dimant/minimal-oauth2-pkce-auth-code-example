using ResourceServer;

var builder = WebApplication.CreateBuilder(args);

// Add CORS configuration
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

// Initialize services
var jwtValidator = new JwtValidator();
var publicKeyProvider = new PublicKeyProvider("http://localhost:5000");

// Middleware to validate bearer tokens
app.Use(async (context, next) =>
{
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
    {
        var token = authHeader.Substring("Bearer ".Length);
        
        // Extract tenant ID from token to fetch public key
        var parts = token.Split('.');
        if (parts.Length == 3)
        {
            try
            {
                // Decode payload to get tenant ID
                var payloadJson = JwtHelper.Base64UrlDecode(parts[1]);
                var payload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(payloadJson);
                
                if (payload != null && payload.TryGetValue("tid", out var tidElement))
                {
                    var tenantId = tidElement.GetString();
                    if (!string.IsNullOrEmpty(tenantId))
                    {
                        // Fetch public key for this tenant
                        var publicKey = await publicKeyProvider.GetPublicKeyAsync(tenantId);
                        
                        if (!string.IsNullOrEmpty(publicKey))
                        {
                            var claims = await jwtValidator.ValidateTokenAsync(token, publicKey);
                            
                            if (claims != null)
                            {
                                // Token is valid, store claims in HttpContext for use in endpoints
                                context.Items["Claims"] = claims;
                                context.Items["IsAuthenticated"] = true;
                            }
                            else
                            {
                                // Invalid token
                                context.Items["IsAuthenticated"] = false;
                                Console.WriteLine("Token validation failed");
                            }
                        }
                        else
                        {
                            context.Items["IsAuthenticated"] = false;
                            Console.WriteLine($"Failed to fetch public key for tenant: {tenantId}");
                        }
                    }
                    else
                    {
                        context.Items["IsAuthenticated"] = false;
                        Console.WriteLine("Tenant ID is empty");
                    }
                }
                else
                {
                    context.Items["IsAuthenticated"] = false;
                    Console.WriteLine("No tid claim found in token");
                }
            }
            catch (Exception ex)
            {
                context.Items["IsAuthenticated"] = false;
                Console.WriteLine($"Error validating token: {ex.Message}");
            }
        }
        else
        {
            context.Items["IsAuthenticated"] = false;
            Console.WriteLine($"Invalid token format: {parts.Length} parts");
        }
    }
    else
    {
        context.Items["IsAuthenticated"] = false;
        Console.WriteLine("No Bearer token found");
    }

    await next();
});

// Protected endpoint - requires valid bearer token
app.MapGet("/protected", (HttpContext context) =>
{
    var isAuthenticated = context.Items["IsAuthenticated"] as bool? ?? false;
    if (!isAuthenticated)
    {
        return Results.Json(new { error = "Unauthorized" }, statusCode: 401);
    }

    var claims = context.Items["Claims"] as Dictionary<string, object>;
    return Results.Json(new
    {
        message = "Access granted to protected resource",
        claims = claims
    });
});

app.Run("http://localhost:5001");
