namespace Api.Gateway;

public sealed class GatewayOptions
{
    public string AuthIntrospectionUrl { get; set; } = string.Empty;
    public string IntrospectionClientId { get; set; } = string.Empty;
    public string IntrospectionClientSecret { get; set; } = string.Empty;
    public string GatewaySyncToken { get; set; } = string.Empty;
    public int PolicyRefreshSeconds { get; set; } = 5;
    public int RevokedCacheMinutes { get; set; } = 5;
    public string RoleScopesSyncUrl { get; set; } = string.Empty;
    public string ConnectionString { get; set; } = string.Empty;
    public List<string> AllowedOrigins { get; set; } = new();
    public List<RouteRule> Routes { get; set; } = new();
    public string AuthSwaggerUrl { get; set; } = string.Empty;
    public string SafeSwaggerUrl { get; set; } = string.Empty;
}

public sealed class RouteRule
{
    public string PathPrefix { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string Upstream { get; set; } = string.Empty;

    public static RouteRule? Match(IEnumerable<RouteRule> rules, PathString path)
    {
        var value = path.HasValue ? path.Value! : string.Empty;
        return rules
            .OrderByDescending(r => r.PathPrefix.Length)
            .FirstOrDefault(r => value.StartsWith(r.PathPrefix, StringComparison.OrdinalIgnoreCase));
    }
}

public sealed record RoleScopeDto(
    string Role,
    string Scope,
    DateTimeOffset UpdatedAt);

public sealed class IntrospectionResponse
{
    public bool Active { get; set; }
    public string? Sub { get; set; }
    public string? Scope { get; set; }
    public string[]? Roles { get; set; }
    public string? Sid { get; set; }
}
