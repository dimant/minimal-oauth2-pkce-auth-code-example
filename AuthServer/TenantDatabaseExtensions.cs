namespace AuthServer;

public static class TenantDatabaseExtensions
{
    public static List<string> GetGrantsForUserAndApp(this TenantDatabase<UserGrants> db, string username, string clientId)
    {
        if (db == null)
        {
            throw new ArgumentNullException(nameof(db));
        }

        var grants = db.Get(username)?.Grants;
        if (grants == null)
        {
            return new List<string>();
        }
        else
        {
            return grants
                .Where(g => g.ClientId == clientId)
                .Select(g => g.Scope)
                .ToList();
        }
    }
}