using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ResourceServer
{
    /// <summary>
    /// JWT (JSON Web Token) Validator for OAuth 2.0 resource servers.
    /// 
    /// This class validates JWT tokens issued by an Authorization Server. It performs
    /// cryptographic verification and claim validation to ensure tokens are legitimate.
    /// 
    /// JWT Structure (Educational Overview):
    /// A JWT consists of three Base64Url-encoded parts separated by dots:
    /// [Header].[Payload].[Signature]
    /// 
    /// 1. HEADER: Contains metadata about the token (algorithm, token type)
    ///    Example: { "alg": "RS256", "typ": "JWT" }
    /// 
    /// 2. PAYLOAD: Contains claims (data about the subject and additional metadata)
    ///    Example: { "sub": "user123", "tid": "tenant-abc", "exp": 1234567890 }
    /// 
    /// 3. SIGNATURE: Cryptographic signature proving the server issued this token
    ///    Computed as: Base64Url(RSA-SHA256(header.payload, privateKey))
    /// 
    /// Validation Flow:
    /// 1. Split token into three parts
    /// 2. Decode and validate header and payload (JSON format)
    /// 3. Check token expiration (exp claim)
    /// 4. Verify the signature using the Authorization Server's public key
    /// 5. Return claims if all checks pass
    /// </summary>
    public class JwtValidator
    {
        /// <summary>
        /// Validates a JWT token and returns the claims if valid.
        /// 
        /// This method performs complete JWT validation including structural validation,
        /// expiration checking, and cryptographic signature verification.
        /// </summary>
        /// <param name="token">The JWT token string to validate</param>
        /// <param name="publicKey">Base64-encoded RSA public key for signature verification</param>
        /// <returns>
        /// A Task that resolves to a dictionary of claims if token is valid, null if invalid.
        /// Claims are the payload contents decoded from the JWT.
        /// </returns>
        public Task<Dictionary<string, object>?> ValidateTokenAsync(string token, string publicKey)
        {
            try
            {
                // STEP 1: Structure Validation - JWT must have exactly 3 parts
                // A malformed token will not have the required structure
                var parts = token.Split('.');
                if (parts.Length != 3)
                {
                    return Task.FromResult<Dictionary<string, object>?>(null);
                }

                var headerEncoded = parts[0];
                var payloadEncoded = parts[1];
                var signatureEncoded = parts[2];

                // STEP 2: Decode and Validate Header
                // The header contains metadata like the algorithm used for signing.
                // For OAuth 2.0, we typically expect "RS256" (RSA with SHA-256).
                var headerJson = JwtHelper.Base64UrlDecode(headerEncoded);
                var header = JsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);
                if (header == null)
                {
                    return Task.FromResult<Dictionary<string, object>?>(null);
                }

                // STEP 3: Decode and Validate Payload
                // The payload (claims set) contains information about the token subject
                // and additional metadata. Format: { "sub": "user", "tid": "tenant", ...}
                var payloadJson = JwtHelper.Base64UrlDecode(payloadEncoded);
                var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson);
                if (payload == null)
                {
                    return Task.FromResult<Dictionary<string, object>?>(null);
                }

                // STEP 4: Expiration Check
                // The "exp" (expiration time) claim is a Unix timestamp indicating when
                // the token expires. Tokens past their expiration time must be rejected
                // to prevent replay attacks and enforce session management.
                if (payload.TryGetValue("exp", out var expElement))
                {
                    var exp = expElement.GetInt64();
                    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    if (now >= exp)
                    {
                        return Task.FromResult<Dictionary<string, object>?>(null); // Token expired
                    }
                }

                // STEP 5: Extract Tenant ID
                // The "tid" (tenant ID) claim identifies which tenant this token belongs to.
                // In a multi-tenant system, this ensures tokens can only be used within
                // their assigned tenant context.
                if (!payload.TryGetValue("tid", out var tidElement))
                {
                    return Task.FromResult<Dictionary<string, object>?>(null);
                }
                var tenantId = tidElement.GetString();
                if (string.IsNullOrEmpty(tenantId))
                {
                    return Task.FromResult<Dictionary<string, object>?>(null);
                }

                // STEP 6: Signature Verification (Critical Security Step)
                // The signature proves that the Authorization Server issued this token.
                // We verify it using the Authorization Server's PUBLIC key with the RS256 algorithm.
                // Only the Authorization Server's PRIVATE key could have created this signature,
                // so a valid signature confirms the token's authenticity and has not been tampered with.
                if (string.IsNullOrEmpty(publicKey))
                {
                    return Task.FromResult<Dictionary<string, object>?>(null);
                }

                // Reconstruct the signed message (header.payload) and verify the signature
                var message = $"{headerEncoded}.{payloadEncoded}";
                
                // Verify the RSA signature using the public key
                if (!VerifySignature(message, signatureEncoded, publicKey))
                {
                    return Task.FromResult<Dictionary<string, object>?>(null); // Invalid signature
                }

                // STEP 7: Return Claims
                // If all validations pass, return the decoded payload as a dictionary
                var result = new Dictionary<string, object>();
                foreach (var kvp in payload)
                {
                    result[kvp.Key] = kvp.Value.GetRawText();
                }

                return Task.FromResult<Dictionary<string, object>?>(result);
            }
            catch
            {
                return Task.FromResult<Dictionary<string, object>?>(null);
            }
        }

        /// <summary>
        /// Verifies the RSA signature of the message using the public key.
        /// 
        /// Educational Note on RS256 (RSA Signature with SHA-256):
        /// RS256 is an asymmetric algorithm that uses an RSA key pair:
        /// - The Authorization Server signs tokens with its PRIVATE key
        /// - Resource Servers verify with the Authorization Server's PUBLIC key
        /// 
        /// This one-way cryptography ensures only the Authorization Server can CREATE valid tokens,
        /// but anyone with the public key can VERIFY them.
        /// 
        /// The verification process:
        /// 1. Decode the signature from Base64Url format
        /// 2. Decode the public key from Base64 format
        /// 3. Use RSA.VerifyData to verify the signature matches the message
        /// </summary>
        private bool VerifySignature(string message, string signatureEncoded, string publicKeyBase64)
        {
            try
            {
                // Decode the signature from Base64Url format
                var signatureBase64 = signatureEncoded.Replace("-", "+").Replace("_", "/");
                while (signatureBase64.Length % 4 != 0)
                {
                    signatureBase64 += "=";
                }
                var signatureBytes = Convert.FromBase64String(signatureBase64);

                // Decode the public key from Base64 format
                var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);

                // Import the public key into an RSA object for verification
                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                    // Verify the signature using RS256 (RSA with PKCS1 padding and SHA256)
                    var messageBytes = Encoding.UTF8.GetBytes(message);
                    return rsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
