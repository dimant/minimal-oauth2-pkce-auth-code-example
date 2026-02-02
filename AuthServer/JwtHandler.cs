using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthServer
{
    public class JwtHandler
    {
        // Hardcoded secret key used to sign JWT tokens
        // In production, this should be stored securely (e.g., in Key Vault)
        // Leaking this secret would allow attackers to forge valid tokens
        // and access any resource that trusts tokens from this auth server.
        private readonly string _secretKey;

        // Issuer identifier for the JWT tokens. This is akin to signing a document
        // with your name to indicate its origin. In this case, we include our name
        // in the 'iss' claim of the JWT payload. To do a digital signature, we
        // temporarily add the secret to the JWT string and then compute an HMAC-SHA256
        // hash of the entire string (header.payload.secret). The resulting hash is
        // included as the signature part of the JWT. Resource servers that receive
        // the JWT can verify the signature by performing the same HMAC-SHA256
        // computation using the shared secret and comparing the result to the
        // signature in the JWT.
        private readonly string _issuer;

        public JwtHandler(string issuer, string secretKey)
        {
            _secretKey = secretKey;
            _issuer = issuer;
        }

        /// <summary>
        /// Generates a JWT access token based on the provided token request information.
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
            var header = new { alg = "HS256", typ = "JWT" };
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
        /// Computes the HMAC-SHA256 signature of the message.
        /// </summary>
        private byte[] ComputeSignature(string message)
        {
            var key = Encoding.UTF8.GetBytes(_secretKey);
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
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