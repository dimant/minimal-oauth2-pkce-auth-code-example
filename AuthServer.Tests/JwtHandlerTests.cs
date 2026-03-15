using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthServer;

namespace AuthServer.Tests;

public class JwtHandlerTests
{
    /// <summary>
    /// Generate a fresh RSA key pair and return the private key as base64.
    /// </summary>
    private static (string privateKeyBase64, RSA rsa) GenerateKeyPair()
    {
        var rsa = RSA.Create(2048);
        var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
        return (Convert.ToBase64String(privateKeyBytes), rsa);
    }

    [Fact]
    public void GenerateAccessToken_ProducesValidThreePartJwt()
    {
        var (privateKey, rsa) = GenerateKeyPair();
        var handler = new JwtHandler("https://auth.example.com", privateKey);

        var token = handler.GenerateAccessToken("tenant1", "app1", "user1",
            new List<string> { "read", "write" }, 3600);

        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);

        rsa.Dispose();
    }

    [Fact]
    public void GenerateAccessToken_ContainsExpectedClaims()
    {
        var (privateKey, rsa) = GenerateKeyPair();
        var handler = new JwtHandler("https://auth.example.com", privateKey);

        var token = handler.GenerateAccessToken("tenant1", "app1", "user1",
            new List<string> { "read", "write" }, 3600);

        // Decode the payload (second part)
        var payloadBase64 = token.Split('.')[1];
        // Restore standard base64 padding
        var padded = payloadBase64.Replace("-", "+").Replace("_", "/");
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        var payload = JsonDocument.Parse(payloadJson);

        Assert.Equal("user1", payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal("app1", payload.RootElement.GetProperty("aud").GetString());
        Assert.Equal("tenant1", payload.RootElement.GetProperty("tid").GetString());
        Assert.Equal("read write", payload.RootElement.GetProperty("scope").GetString());
        Assert.Equal("https://auth.example.com", payload.RootElement.GetProperty("iss").GetString());
        Assert.True(payload.RootElement.TryGetProperty("exp", out _));
        Assert.True(payload.RootElement.TryGetProperty("iat", out _));

        rsa.Dispose();
    }

    [Fact]
    public void GenerateAccessToken_SignatureIsVerifiableWithPublicKey()
    {
        var (privateKey, rsa) = GenerateKeyPair();
        var handler = new JwtHandler("https://auth.example.com", privateKey);

        var token = handler.GenerateAccessToken("tenant1", "app1", "user1",
            new List<string> { "read" }, 3600);

        var parts = token.Split('.');
        var message = $"{parts[0]}.{parts[1]}";
        var signatureBase64 = parts[2].Replace("-", "+").Replace("_", "/");
        switch (signatureBase64.Length % 4)
        {
            case 2: signatureBase64 += "=="; break;
            case 3: signatureBase64 += "="; break;
        }
        var signature = Convert.FromBase64String(signatureBase64);

        // Verify the signature using the public key
        bool isValid = rsa.VerifyData(
            Encoding.UTF8.GetBytes(message),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        Assert.True(isValid);

        rsa.Dispose();
    }

    [Fact]
    public void GenerateAccessToken_ExpirationIsCorrect()
    {
        var (privateKey, rsa) = GenerateKeyPair();
        var handler = new JwtHandler("https://auth.example.com", privateKey);
        int expirationSeconds = 7200;

        var beforeGeneration = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var token = handler.GenerateAccessToken("tenant1", "app1", "user1",
            new List<string> { "read" }, expirationSeconds);
        var afterGeneration = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Decode payload
        var payloadBase64 = token.Split('.')[1].Replace("-", "+").Replace("_", "/");
        switch (payloadBase64.Length % 4)
        {
            case 2: payloadBase64 += "=="; break;
            case 3: payloadBase64 += "="; break;
        }
        var payload = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payloadBase64)));

        var iat = payload.RootElement.GetProperty("iat").GetInt64();
        var exp = payload.RootElement.GetProperty("exp").GetInt64();

        Assert.InRange(iat, beforeGeneration, afterGeneration);
        Assert.Equal(expirationSeconds, exp - iat);

        rsa.Dispose();
    }
}
