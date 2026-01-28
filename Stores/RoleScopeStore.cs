using System.Collections.Immutable;

namespace Api.Gateway.Stores;

public sealed class RoleScopeStore
{
    private ImmutableDictionary<string, ImmutableHashSet<string>> _roleScopes =
        ImmutableDictionary<string, ImmutableHashSet<string>>.Empty;

    public void Update(IEnumerable<RoleScopeDto> scopes)
    {
        var builder = ImmutableDictionary.CreateBuilder<string, ImmutableHashSet<string>>();
        foreach (var dto in scopes)
        {
            var role = dto.Role.Trim().ToLowerInvariant();
            var scope = dto.Scope.Trim().ToLowerInvariant();
            if (!builder.TryGetValue(role, out var set))
            {
                set = ImmutableHashSet<string>.Empty;
            }
            builder[role] = set.Add(scope);
        }

        _roleScopes = builder.ToImmutable();
    }

    public bool HasScope(IEnumerable<string> roles, string scope)
    {
        var s = scope.Trim().ToLowerInvariant();
        foreach (var role in roles)
        {
            var r = role.Trim().ToLowerInvariant();
            if (_roleScopes.TryGetValue(r, out var scopes) && scopes.Contains(s))
            {
                return true;
            }
        }

        return false;
    }

    public IReadOnlyDictionary<string, IReadOnlyCollection<string>> Snapshot()
    {
        var result = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in _roleScopes)
        {
            result[entry.Key] = entry.Value.ToArray();
        }
        return result;
    }
}
