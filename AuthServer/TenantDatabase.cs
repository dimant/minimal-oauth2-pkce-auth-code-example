namespace AuthServer
{
    public interface ITenantData
    {
        string GetId();
    }

    public class Tenant
    {
        private readonly string _tenantId;

        public string GetId() => _tenantId;

        public SigningCertificateHandler SigningCertificateHandler { get; }

        public TenantDatabase<AppInfo> AppRegistrations { get; }

        public TenantDatabase<UserInfo> UserRegistrations { get; }

        public TenantDatabase<UserGrants> UserGrants { get; }

        public Tenant(string tenantId)
        {
            _tenantId = tenantId;
            SigningCertificateHandler = new SigningCertificateHandler(tenantId);
            AppRegistrations = new TenantDatabase<AppInfo>(tenantId);
            UserRegistrations = new TenantDatabase<UserInfo>(tenantId);
            UserGrants = new TenantDatabase<UserGrants>(tenantId);
        }
    }

    /// <summary>
    /// Application information.
    /// </summary>
    public class AppInfo : ITenantData
    {
        public string ClientId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public string[] Scopes { get; set; } = Array.Empty<string>();
        public string GetId() => ClientId;
    }

    /// <summary>
    /// User information.
    /// </summary>
    public class UserInfo : ITenantData
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string GetId() => Username;
    }

    public class UserGrants : ITenantData
    {
        public string Username { get; set; } = string.Empty;
        public List<(string ClientId, string Scope)> Grants { get; set; } = 
            new List<(string ClientId, string Scope)>();

        public string GetId() => Username;
    }

    public class AuthorizationCodeInfo : ITenantData
    {
        public string AuthorizationCode { get; set; } = string.Empty;
        public string CodeChallenge { get; set; } = string.Empty;
        public string CodeChallengeMethod { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string[] Scopes { get; set; } = Array.Empty<string>();
        public string GetId() => AuthorizationCode;
    }

    /// <summary>
    /// Tenant-specific database for storing data.
    /// </summary>
    public class TenantDatabase<T> where T : ITenantData
    {
        private readonly string _tenantId;

        private readonly Dictionary<string, T> _database;

        public string GetId() => _tenantId;

        public TenantDatabase(string tenantId)
        {
            _tenantId = tenantId;
            _database = new Dictionary<string, T>();
        }

        /// <summary>
        /// Register an application for a tenant.
        /// </summary>
        /// <param name="tenant">Tenant identifier.</param>
        /// <param name="data">Data to register for the tenant.</param>
        /// <returns></returns>
        public void Register(T data)
        {
            if (!_database.ContainsKey(data.GetId()))
            {
                _database[data.GetId()] = default!;
            }
            _database[data.GetId()] = data;
        }

        /// <summary>
        /// Get data for a tenant and data ID.
        /// </summary>
        /// <param name="tenant">Tenant identifier.</param>
        /// <param name="id">data identifier.</param>
        /// <returns>data object or null if not found.</returns>
        public T? Get(string id)
        {
            if (_database.TryGetValue(id, out var data))
            {
                return data;
            }
            return default(T);
        }
    }
}