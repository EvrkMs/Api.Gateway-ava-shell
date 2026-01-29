using Api.Gateway.Data;
using Api.Gateway.Models;
using Api.Gateway.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Api.Gateway.Services;

public sealed class DatabaseSyncService : BackgroundService
{
    private readonly IOptions<GatewayOptions> _options;
    private readonly EndpointStore _endpointStore;
    private readonly PermissionStore _permissionStore;
    private readonly IDbContextFactory<GatewayDbContext> _dbFactory;

    public DatabaseSyncService(
        IOptions<GatewayOptions> options,
        EndpointStore endpointStore,
        PermissionStore permissionStore,
        IDbContextFactory<GatewayDbContext> dbFactory)
    {
        _options = options;
        _endpointStore = endpointStore;
        _permissionStore = permissionStore;
        _dbFactory = dbFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var connectionString = _options.Value.ConnectionString;
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return;
        }

        await using (var db = await _dbFactory.CreateDbContextAsync(stoppingToken))
        {
            await db.Database.MigrateAsync(stoppingToken);

            var existing = await db.GatewayEndpoints
                .ToListAsync(stoppingToken);
            var existingMap = existing
                .ToDictionary(e => e.NormalizedName, StringComparer.OrdinalIgnoreCase);
            var now = DateTimeOffset.UtcNow;

            var toAdd = EndpointCatalog.All
                .Where(e => !existingMap.ContainsKey(e.NormalizedName))
                .ToList();
            if (toAdd.Count > 0)
            {
                await db.GatewayEndpoints.AddRangeAsync(toAdd, stoppingToken);
            }

            foreach (var endpoint in EndpointCatalog.All)
            {
                if (!existingMap.TryGetValue(endpoint.NormalizedName, out var current))
                {
                    continue;
                }

                if (!string.Equals(current.Path, endpoint.Path, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(current.Scope, endpoint.Scope, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(current.DisplayName, endpoint.DisplayName, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(current.Description, endpoint.Description, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(current.Method, endpoint.Method, StringComparison.OrdinalIgnoreCase))
                {
                    current.Path = endpoint.Path;
                    current.Scope = endpoint.Scope;
                    current.DisplayName = endpoint.DisplayName;
                    current.Description = endpoint.Description;
                    current.Method = endpoint.Method;
                    current.UpdatedAt = now;
                }
            }

            await db.SaveChangesAsync(stoppingToken);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            await RefreshAsync(stoppingToken);
            var delay = TimeSpan.FromSeconds(Math.Max(1, _options.Value.PolicyRefreshSeconds));
            await Task.Delay(delay, stoppingToken);
        }
    }

    private async Task RefreshAsync(CancellationToken ct)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var endpoints = await db.GatewayEndpoints
            .AsNoTracking()
            .ToListAsync(ct);
        _endpointStore.Update(endpoints);

        var permissions = await db.RolePermissions
            .AsNoTracking()
            .ToListAsync(ct);
        _permissionStore.Update(permissions);
    }
}
