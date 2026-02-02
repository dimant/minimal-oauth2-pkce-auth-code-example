using System.Text.Json;

namespace ResourceServer
{
    public class PublicKeyProvider
    {
        private readonly HttpClient _httpClient;
        private readonly string _authServerUrl;
        private readonly Dictionary<string, string> _publicKeyCache = new();

        public PublicKeyProvider(string authServerUrl)
        {
            _authServerUrl = authServerUrl;
            _httpClient = new HttpClient();
        }

        /// <summary>
        /// Fetches the public key from the auth server for a given tenant.
        /// </summary>
        public async Task<string?> GetPublicKeyAsync(string tenantId)
        {
            // Check cache first
            if (_publicKeyCache.TryGetValue(tenantId, out var cachedKey))
            {
                return cachedKey;
            }

            try
            {
                var url = $"{_authServerUrl}/{tenantId}/oauth2/v2.0/public-key";
                var response = await _httpClient.GetAsync(url);
                
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }

                var content = await response.Content.ReadAsStringAsync();
                var jsonDoc = JsonSerializer.Deserialize<JsonElement>(content);
                
                if (jsonDoc.TryGetProperty("public_key", out var keyElement))
                {
                    var publicKey = keyElement.GetString();
                    if (!string.IsNullOrEmpty(publicKey))
                    {
                        _publicKeyCache[tenantId] = publicKey;
                        return publicKey;
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }

            return null;
        }
    }
}
