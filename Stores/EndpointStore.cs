using System.Collections.Immutable;
using Api.Gateway.Models;

namespace Api.Gateway.Stores;

public sealed class EndpointStore
{
    private ImmutableArray<GatewayEndpoint> _endpoints = ImmutableArray<GatewayEndpoint>.Empty;

    public void Update(IEnumerable<GatewayEndpoint> endpoints)
    {
        _endpoints = endpoints.ToImmutableArray();
    }

    public IReadOnlyList<GatewayEndpoint> GetAll()
    {
        return _endpoints;
    }

    public GatewayEndpoint? Match(string method, PathString path)
    {
        var normalizedPath = NormalizePath(path);
        var candidates = _endpoints
            .Where(e => string.Equals(e.Method, method, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(e => e.Path.Length);

        foreach (var endpoint in candidates)
        {
            if (PathMatches(endpoint.Path, normalizedPath))
            {
                return endpoint;
            }
        }

        return null;
    }

    private static string NormalizePath(PathString path)
    {
        var value = path.HasValue ? path.Value! : "/";
        if (value.Length > 1 && value.EndsWith('/'))
        {
            value = value.TrimEnd('/');
        }
        return value;
    }

    private static bool PathMatches(string template, string actual)
    {
        var t = NormalizeRaw(template);
        var a = NormalizeRaw(actual);

        var tParts = t.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var aParts = a.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (tParts.Length != aParts.Length)
        {
            return false;
        }

        for (var i = 0; i < tParts.Length; i++)
        {
            var tp = tParts[i];
            var ap = aParts[i];
            if (IsWildcard(tp))
            {
                continue;
            }

            if (!string.Equals(tp, ap, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static string NormalizeRaw(string value)
    {
        var v = value;
        if (v.Length > 1 && v.EndsWith('/'))
        {
            v = v.TrimEnd('/');
        }
        return v;
    }

    private static bool IsWildcard(string segment)
    {
        if (segment.StartsWith('{') && segment.EndsWith('}'))
        {
            return true;
        }
        return segment.Contains(':') && segment.StartsWith('{');
    }
}
