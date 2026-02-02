using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthServer
{
    public class JwtHandler
    {
        // RSA private key for signing JWT tokens with RS256 algorithm
        // The private key is used to create cryptographic signatures
        // Resource servers will validate these signatures using the corresponding public key
        private readonly byte[] _privateKeyBytes;

        // Issuer identifier for the JWT tokens
        private readonly string _issuer;

        public JwtHandler(string issuer, string privateKeyBase64)
        {
            _privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            _issuer = issuer;
        }

        /// <summary>
        /// Generates a JWT access token using RS256 (RSA with SHA256).
        /// JWT format: header.payload.signature (all base64url encoded)
        /// </summary>
        /// <param name="tenantId">The tenant ID.</param>
        /// <param name="clientId">The client ID requesting the token.</param>
        /// <param name="username">The username for whom the token is being issued.</param>
        /// <param name="scopes">The scopes granted to the token.</param>
        /// <returns>A JWT access token as a string.</returns>
        public string GenerateAccessToken(
            string tenantId,
            string clientId,
            string username,
            List<string> scopes,
            int expirationSeconds)
        {
            // Header
            var header = new { alg = "RS256", typ = "JWT" };
            var headerJson = JsonSerializer.Serialize(header);
            var headerEncoded = Base64UrlEncode(headerJson);

            // Payload
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var payload = new
            {
                sub = username,
                aud = clientId,
                tid = tenantId,
                scope = string.Join(" ", scopes),
                iss = _issuer,
                iat = now,
                exp = now + expirationSeconds
            };
            var payloadJson = JsonSerializer.Serialize(payload);
            var payloadEncoded = Base64UrlEncode(payloadJson);

            // Signature
            var message = $"{headerEncoded}.{payloadEncoded}";
            var signature = ComputeSignature(message);
            var signatureEncoded = Base64UrlEncode(signature);

            // Complete JWT
            return $"{message}.{signatureEncoded}";
        }

        /// <summary>
        /// Computes the RSA-SHA256 signature of the message.
        /// </summary>
        private byte[] ComputeSignature(string message)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(_privateKeyBytes, out _);
                return rsa.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        /// <summary>
        /// Encodes a string to Base64Url format (URL-safe base64).
        /// </summary>
        private string Base64UrlEncode(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            return Base64UrlEncode(bytes);
        }

        /// <summary>
        /// Encodes bytes to Base64Url format (URL-safe base64).
        /// </summary>
        private string Base64UrlEncode(byte[] input)
        {
            var base64 = Convert.ToBase64String(input);
            // Convert to URL-safe base64
            return base64.Replace("+", "-")
                         .Replace("/", "_")
                         .TrimEnd('=');
        }
    }
}