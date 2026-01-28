using System.Collections.Immutable;
using Api.Gateway.Models;

namespace Api.Gateway.Stores;

public sealed class PermissionStore
{
    private ImmutableDictionary<(string Role, Guid EndpointId), bool> _permissions =
        ImmutableDictionary<(string Role, Guid EndpointId), bool>.Empty;

    public void Update(IEnumerable<RolePermission> permissions)
    {
        var builder = ImmutableDictionary.CreateBuilder<(string Role, Guid EndpointId), bool>();
        foreach (var permission in permissions)
        {
            var key = (permission.Role.Trim().ToLowerInvariant(), permission.EndpointId);
            builder[key] = permission.IsAllowed;
        }
        _permissions = builder.ToImmutable();
    }

    public bool IsAllowed(IEnumerable<string> roles, Guid endpointId)
    {
        var allowed = false;
        foreach (var role in roles)
        {
            var key = (role.Trim().ToLowerInvariant(), endpointId);
            if (_permissions.TryGetValue(key, out var isAllowed))
            {
                if (!isAllowed)
                {
                    return false;
                }

                allowed = true;
            }
        }

        return allowed;
    }
}
