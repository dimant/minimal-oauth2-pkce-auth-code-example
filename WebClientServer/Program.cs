var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Handle OAuth2 callback by redirecting to index.html with the code parameter
app.MapGet("/callback", (string code) =>
{
    return Results.Redirect($"/?code={code}");
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.Run("http://+:5003");
