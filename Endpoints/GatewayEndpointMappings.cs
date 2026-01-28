using System.Text;
using System.Text.Json;
using Api.Gateway.Data;
using Api.Gateway.Http;
using Api.Gateway.Models;
using Api.Gateway.Security;
using Api.Gateway.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace Api.Gateway.Endpoints;

public static class GatewayEndpointMappings
{
    public static void MapHealthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
    }

    public static void MapContractEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/contracts/auth", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            if (string.IsNullOrWhiteSpace(options.AuthSwaggerUrl))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("auth swagger not configured");
                return;
            }

            var http = context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("gateway");
            using var response = await http.GetAsync(options.AuthSwaggerUrl, context.RequestAborted);
            context.Response.StatusCode = (int)response.StatusCode;
            foreach (var header in response.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            foreach (var header in response.Content.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            context.Response.Headers.Remove("transfer-encoding");
            await response.Content.CopyToAsync(context.Response.Body);
        });

        app.MapGet("/api/contracts/safe", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            if (string.IsNullOrWhiteSpace(options.SafeSwaggerUrl))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("safe swagger not configured");
                return;
            }

            var http = context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("gateway");
            using var response = await http.GetAsync(options.SafeSwaggerUrl, context.RequestAborted);
            context.Response.StatusCode = (int)response.StatusCode;
            foreach (var header in response.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            foreach (var header in response.Content.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            context.Response.Headers.Remove("transfer-encoding");
            await response.Content.CopyToAsync(context.Response.Body);
        });
    }

    public static void MapGatewayAdminEndpoints(this IEndpointRouteBuilder app, JsonSerializerOptions jsonOptions)
    {
        app.MapGet("/api/gateway/endpoints", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.ConnectionString))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("gateway database disabled");
                return;
            }

            await using var db = await context.RequestServices
                .GetRequiredService<IDbContextFactory<GatewayDbContext>>()
                .CreateDbContextAsync(context.RequestAborted);
            var endpoints = await db.GatewayEndpoints
                .AsNoTracking()
                .OrderBy(e => e.NormalizedName)
                .ToListAsync(context.RequestAborted);
            await context.Response.WriteAsJsonAsync(endpoints, jsonOptions, context.RequestAborted);
        }).WithTags("Gateway Admin");

        app.MapGet("/api/gateway/permissions", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.ConnectionString))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("gateway database disabled");
                return;
            }

            var roleFilter = context.Request.Query["role"].ToString();
            await using var db = await context.RequestServices
                .GetRequiredService<IDbContextFactory<GatewayDbContext>>()
                .CreateDbContextAsync(context.RequestAborted);
            var permissions = await db.RolePermissions
                .AsNoTracking()
                .ToListAsync(context.RequestAborted);
            if (!string.IsNullOrWhiteSpace(roleFilter))
            {
                permissions = permissions
                    .Where(p => string.Equals(p.Role, roleFilter, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            var response = permissions
                .Select(p => new GatewayPermissionResponse(p.Id, p.Role, p.EndpointId, p.IsAllowed, p.UpdatedAt))
                .OrderBy(p => p.Role)
                .ThenBy(p => p.EndpointId);

            await context.Response.WriteAsJsonAsync(response, jsonOptions, context.RequestAborted);
        }).WithTags("Gateway Admin");

        app.MapPut("/api/gateway/permissions", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            var permissionStore = context.RequestServices.GetRequiredService<PermissionStore>();
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.ConnectionString))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("gateway database disabled");
                return;
            }

            var payload = await context.Request.ReadFromJsonAsync<List<GatewayPermissionRequest>>(jsonOptions, context.RequestAborted);
            if (payload is null || payload.Count == 0)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("empty payload");
                return;
            }

            var now = DateTimeOffset.UtcNow;
            var items = payload
                .Where(p => !string.IsNullOrWhiteSpace(p.Role) && p.EndpointId != Guid.Empty)
                .Select(p => new RolePermission
                {
                    Id = Guid.NewGuid(),
                    Role = p.Role.Trim(),
                    EndpointId = p.EndpointId,
                    IsAllowed = p.IsAllowed,
                    UpdatedAt = now
                })
                .ToList();

            await using var db = await context.RequestServices
                .GetRequiredService<IDbContextFactory<GatewayDbContext>>()
                .CreateDbContextAsync(context.RequestAborted);
            foreach (var item in items)
            {
                var existing = await db.RolePermissions
                    .FirstOrDefaultAsync(p => p.Role == item.Role && p.EndpointId == item.EndpointId, context.RequestAborted);
                if (existing is null)
                {
                    db.RolePermissions.Add(item);
                }
                else
                {
                    existing.IsAllowed = item.IsAllowed;
                    existing.UpdatedAt = item.UpdatedAt;
                }
            }
            await db.SaveChangesAsync(context.RequestAborted);
            var updated = await db.RolePermissions.AsNoTracking().ToListAsync(context.RequestAborted);
            permissionStore.Update(updated);

            context.Response.StatusCode = StatusCodes.Status204NoContent;
        }).WithTags("Gateway Admin");

        app.MapDelete("/api/gateway/permissions/{role}/{endpointId:guid}", async (HttpContext context, string role, Guid endpointId) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            var permissionStore = context.RequestServices.GetRequiredService<PermissionStore>();
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.ConnectionString))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("gateway database disabled");
                return;
            }

            await using var db = await context.RequestServices
                .GetRequiredService<IDbContextFactory<GatewayDbContext>>()
                .CreateDbContextAsync(context.RequestAborted);
            var existing = await db.RolePermissions
                .FirstOrDefaultAsync(p => p.Role == role && p.EndpointId == endpointId, context.RequestAborted);
            if (existing is not null)
            {
                db.RolePermissions.Remove(existing);
                await db.SaveChangesAsync(context.RequestAborted);
            }
            var updated = await db.RolePermissions.AsNoTracking().ToListAsync(context.RequestAborted);
            permissionStore.Update(updated);
            context.Response.StatusCode = StatusCodes.Status204NoContent;
        }).WithTags("Gateway Admin");

        app.MapGet("/api/gateway/role-scopes", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            var roleScopeStore = context.RequestServices.GetRequiredService<RoleScopeStore>();
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            var snapshot = roleScopeStore.Snapshot();
            await context.Response.WriteAsJsonAsync(snapshot, jsonOptions, context.RequestAborted);
        }).WithTags("Gateway Admin");

        app.MapPut("/api/gateway/role-scopes", async (HttpContext context) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            var roleScopeStore = context.RequestServices.GetRequiredService<RoleScopeStore>();
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.RoleScopesSyncUrl) || string.IsNullOrWhiteSpace(options.GatewaySyncToken))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("role scopes sync not configured");
                return;
            }

            var payload = await context.Request.ReadFromJsonAsync<List<RoleScopeDto>>(jsonOptions, context.RequestAborted);
            if (payload is null || payload.Count == 0)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("empty payload");
                return;
            }

            var http = context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("gateway");
            using var request = new HttpRequestMessage(HttpMethod.Put, options.RoleScopesSyncUrl);
            request.Headers.TryAddWithoutValidation("X-Gateway-Token", options.GatewaySyncToken);
            request.Content = new StringContent(JsonSerializer.Serialize(payload, jsonOptions), Encoding.UTF8, "application/json");

            using var response = await http.SendAsync(request, context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                context.Response.StatusCode = (int)response.StatusCode;
                await response.Content.CopyToAsync(context.Response.Body);
                return;
            }

            var updated = await FetchRoleScopesAsync(http, options, jsonOptions, context.RequestAborted);
            if (updated is not null)
            {
                roleScopeStore.Update(updated);
            }

            context.Response.StatusCode = StatusCodes.Status204NoContent;
        }).WithTags("Gateway Admin");

        app.MapDelete("/api/gateway/role-scopes/{role}/{scope}", async (HttpContext context, string role, string scope) =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            var roleScopeStore = context.RequestServices.GetRequiredService<RoleScopeStore>();
            if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.RoleScopesSyncUrl) || string.IsNullOrWhiteSpace(options.GatewaySyncToken))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("role scopes sync not configured");
                return;
            }

            var http = context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("gateway");
            using var request = new HttpRequestMessage(HttpMethod.Delete, $"{options.RoleScopesSyncUrl.TrimEnd('/')}/{Uri.EscapeDataString(role)}/{Uri.EscapeDataString(scope)}");
            request.Headers.TryAddWithoutValidation("X-Gateway-Token", options.GatewaySyncToken);

            using var response = await http.SendAsync(request, context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                context.Response.StatusCode = (int)response.StatusCode;
                await response.Content.CopyToAsync(context.Response.Body);
                return;
            }

            var updated = await FetchRoleScopesAsync(http, options, jsonOptions, context.RequestAborted);
            if (updated is not null)
            {
                roleScopeStore.Update(updated);
            }

            context.Response.StatusCode = StatusCodes.Status204NoContent;
        }).WithTags("Gateway Admin");
    }

    public static void MapProxyEndpoint(this IEndpointRouteBuilder app, JsonSerializerOptions jsonOptions)
    {
        app.Map("/{**catchall}", async context =>
        {
            var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
            var endpointStore = context.RequestServices.GetRequiredService<EndpointStore>();
            var permissionStore = context.RequestServices.GetRequiredService<PermissionStore>();
            var roleScopeStore = context.RequestServices.GetRequiredService<RoleScopeStore>();
            var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
            var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();

            CorsHelpers.ApplyCors(context, options.AllowedOrigins);
            if (HttpMethods.IsOptions(context.Request.Method))
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            var endpoint = endpointStore.Match(context.Request.Method, context.Request.Path);
            if (endpoint is null)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("not found");
                return;
            }

            var route = RouteRule.Match(options.Routes, context.Request.Path);
            if (route is null)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("not found");
                return;
            }

            if (!GatewayAuthHelpers.TryGetBearerToken(context.Request, out var token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("missing token");
                return;
            }

            var tokenKey = GatewayAuthHelpers.ComputeTokenKey(token);
            if (cache.TryGetValue(tokenKey, out _))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("token revoked");
                return;
            }

            var introspection = await GatewayAuthHelpers.IntrospectAsync(
                httpClientFactory,
                options,
                token,
                jsonOptions,
                context.RequestAborted);
            if (introspection is null || !introspection.Active)
            {
                cache.Set(tokenKey, true, TimeSpan.FromMinutes(options.RevokedCacheMinutes));
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("token inactive");
                return;
            }

            var roles = introspection.Roles ?? Array.Empty<string>();
            var isRoot = roles.Any(r => string.Equals(r, "root", StringComparison.OrdinalIgnoreCase));
            if (!isRoot && !roleScopeStore.HasScope(roles, endpoint.Scope))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("forbidden");
                return;
            }

            if (!isRoot && !permissionStore.IsAllowed(roles, endpoint.Id))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("forbidden");
                return;
            }

            var gatewayToken = string.Equals(route.Scope, "auth", StringComparison.OrdinalIgnoreCase)
                ? options.GatewaySyncToken
                : null;
            var userId = introspection.Sub;
            var userName = introspection.PreferredUsername
                ?? introspection.Name
                ?? introspection.Email
                ?? JwtClaimsExtractor.ExtractUserNameFromToken(token);
            await ProxyHelpers.ProxyAsync(context, httpClientFactory, route.Upstream, gatewayToken, userId, userName);
        });
    }

    private static async Task<List<RoleScopeDto>?> FetchRoleScopesAsync(
        HttpClient http,
        GatewayOptions options,
        JsonSerializerOptions jsonOptions,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.RoleScopesSyncUrl) || string.IsNullOrWhiteSpace(options.GatewaySyncToken))
        {
            return null;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, options.RoleScopesSyncUrl);
        request.Headers.TryAddWithoutValidation("X-Gateway-Token", options.GatewaySyncToken);

        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var stream = await response.Content.ReadAsStreamAsync(ct);
        return await JsonSerializer.DeserializeAsync<List<RoleScopeDto>>(stream, jsonOptions, ct);
    }
}
