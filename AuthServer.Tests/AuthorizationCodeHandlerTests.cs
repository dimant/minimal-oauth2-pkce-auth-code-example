using System.Security.Cryptography;
using Xunit;
using AuthServer;

namespace AuthServer.Tests;

public class AuthorizationCodeHandlerTests
{
    /// <summary>
    /// Helper to generate a valid PKCE code_verifier and code_challenge pair.
    /// Mirrors the same process the client performs:
    /// 1. Generate random bytes as the verifier
    /// 2. SHA256 hash the verifier to produce the challenge
    /// </summary>
    private static (string codeVerifier, string codeChallenge) GeneratePkce()
    {
        byte[] randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        string codeVerifier = Convert.ToBase64String(randomBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');

        using var sha256 = SHA256.Create();
        byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));
        string codeChallenge = Convert.ToBase64String(hashBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');

        return (codeVerifier, codeChallenge);
    }

    [Fact]
    public void ValidateCode_WithCorrectVerifier_ReturnsRecord()
    {
        var handler = new AuthorizationCodeHandler();
        var (verifier, challenge) = GeneratePkce();

        var code = handler.GenerateCode("tenant1", "app1", "user1",
            new List<string> { "read" }, challenge, "S256");

        var result = handler.ValidateCode(code, verifier);

        Assert.NotNull(result);
        Assert.Equal("tenant1", result.TenantId);
        Assert.Equal("app1", result.ClientId);
        Assert.Equal("user1", result.Username);
        Assert.Contains("read", result.Scopes);
    }

    [Fact]
    public void ValidateCode_WithWrongVerifier_ReturnsNull()
    {
        var handler = new AuthorizationCodeHandler();
        var (_, challenge) = GeneratePkce();

        var code = handler.GenerateCode("tenant1", "app1", "user1",
            new List<string> { "read" }, challenge, "S256");

        var result = handler.ValidateCode(code, "wrong-verifier-value");

        Assert.Null(result);
    }

    [Fact]
    public void ValidateCode_WithInvalidCode_ReturnsNull()
    {
        var handler = new AuthorizationCodeHandler();

        var result = handler.ValidateCode("nonexistent-code", "some-verifier");

        Assert.Null(result);
    }

    [Fact]
    public void ValidateCode_UsedTwice_ReturnsNullOnSecondAttempt()
    {
        // RFC 6749 §4.1.2: Authorization codes MUST be single-use
        var handler = new AuthorizationCodeHandler();
        var (verifier, challenge) = GeneratePkce();

        var code = handler.GenerateCode("tenant1", "app1", "user1",
            new List<string> { "read" }, challenge, "S256");

        var first = handler.ValidateCode(code, verifier);
        Assert.NotNull(first);

        var second = handler.ValidateCode(code, verifier);
        Assert.Null(second);
    }

    [Fact]
    public void GenerateCode_ProducesUniqueCodesEachTime()
    {
        var handler = new AuthorizationCodeHandler();
        var (_, challenge) = GeneratePkce();

        var code1 = handler.GenerateCode("tenant1", "app1", "user1",
            new List<string> { "read" }, challenge, "S256");
        var code2 = handler.GenerateCode("tenant1", "app1", "user1",
            new List<string> { "read" }, challenge, "S256");

        Assert.NotEqual(code1, code2);
    }
}
