using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Api.Gateway;
using Api.Gateway.Models;
using Api.Gateway.Services;
using Api.Gateway.Stores;
using Api.Gateway.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var JsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
var HopByHopHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailers",
    "Transfer-Encoding",
    "Upgrade"
};

builder.Services.AddMemoryCache();
builder.Services.AddHttpClient("gateway")
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
        SslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, _, _, _) => true
        }
    });

builder.Services.Configure<GatewayOptions>(builder.Configuration.GetSection("Gateway"));
var gatewayConnectionString = builder.Configuration["Gateway:ConnectionString"] ?? string.Empty;
builder.Services.AddDbContextFactory<GatewayDbContext>(options =>
{
    options.UseNpgsql(gatewayConnectionString);
});
builder.Services.AddSingleton<EndpointStore>();
builder.Services.AddSingleton<PermissionStore>();
builder.Services.AddSingleton<RoleScopeStore>();
builder.Services.AddHostedService<DatabaseSyncService>();
builder.Services.AddHostedService<RoleScopeSyncService>();

var app = builder.Build();

if (!string.IsNullOrWhiteSpace(builder.Configuration["Gateway:ConnectionString"]))
{
    using var scope = app.Services.CreateScope();
    var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<GatewayDbContext>>();
    await using var db = await dbFactory.CreateDbContextAsync();
    await db.Database.MigrateAsync();
}

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

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

app.MapGet("/api/gateway/endpoints", async (HttpContext context) =>
{
    var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
    if (!await EnsureRootAsync(context, options))
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
    await context.Response.WriteAsJsonAsync(endpoints, JsonOptions, context.RequestAborted);
});

app.MapGet("/api/gateway/permissions", async (HttpContext context) =>
{
    var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
    if (!await EnsureRootAsync(context, options))
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

    await context.Response.WriteAsJsonAsync(response, JsonOptions, context.RequestAborted);
});

app.MapPut("/api/gateway/permissions", async (HttpContext context) =>
{
    var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
    var permissionStore = context.RequestServices.GetRequiredService<PermissionStore>();
    if (!await EnsureRootAsync(context, options))
    {
        return;
    }

    if (string.IsNullOrWhiteSpace(options.ConnectionString))
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await context.Response.WriteAsync("gateway database disabled");
        return;
    }

    var payload = await context.Request.ReadFromJsonAsync<List<GatewayPermissionRequest>>(JsonOptions, context.RequestAborted);
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
});

app.MapDelete("/api/gateway/permissions/{role}/{endpointId:guid}", async (HttpContext context, string role, Guid endpointId) =>
{
    var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
    var permissionStore = context.RequestServices.GetRequiredService<PermissionStore>();
    if (!await EnsureRootAsync(context, options))
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
});

app.MapGet("/api/gateway/role-scopes", async (HttpContext context) =>
{
    var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
    var roleScopeStore = context.RequestServices.GetRequiredService<RoleScopeStore>();
    if (!await EnsureRootAsync(context, options))
    {
        return;
    }

    var snapshot = roleScopeStore.Snapshot();
    await context.Response.WriteAsJsonAsync(snapshot, JsonOptions, context.RequestAborted);
});

app.Map("/{**catchall}", async context =>
{
    var options = context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>().Value;
    var endpointStore = context.RequestServices.GetRequiredService<EndpointStore>();
    var permissionStore = context.RequestServices.GetRequiredService<PermissionStore>();
    var roleScopeStore = context.RequestServices.GetRequiredService<RoleScopeStore>();
    var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
    var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();

    ApplyCors(context, options.AllowedOrigins);
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

    if (!TryGetBearerToken(context.Request, out var token))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("missing token");
        return;
    }

    var tokenKey = ComputeTokenKey(token);
    if (cache.TryGetValue(tokenKey, out _))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("token revoked");
        return;
    }

    var introspection = await IntrospectAsync(httpClientFactory, options, token, context.RequestAborted);
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
    await ProxyAsync(context, httpClientFactory, route.Upstream, gatewayToken);
});

app.Run();

async Task<bool> EnsureRootAsync(HttpContext context, GatewayOptions options)
{
    var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
    var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();

    ApplyCors(context, options.AllowedOrigins);
    if (HttpMethods.IsOptions(context.Request.Method))
    {
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return false;
    }

    if (!TryGetBearerToken(context.Request, out var token))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("missing token");
        return false;
    }

    var tokenKey = ComputeTokenKey(token);
    if (cache.TryGetValue(tokenKey, out _))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("token revoked");
        return false;
    }

    var introspection = await IntrospectAsync(httpClientFactory, options, token, context.RequestAborted);
    if (introspection is null || !introspection.Active)
    {
        cache.Set(tokenKey, true, TimeSpan.FromMinutes(options.RevokedCacheMinutes));
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("token inactive");
        return false;
    }

    var roles = introspection.Roles ?? Array.Empty<string>();
    var isRoot = roles.Any(r => string.Equals(r, "root", StringComparison.OrdinalIgnoreCase));
    if (!isRoot)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsync("forbidden");
        return false;
    }

    return true;
}

void ApplyCors(HttpContext context, IReadOnlyCollection<string> allowedOrigins)
{
    var origin = context.Request.Headers.Origin.ToString();
    if (string.IsNullOrWhiteSpace(origin))
    {
        return;
    }

    if (!allowedOrigins.Any(o => string.Equals(o, origin, StringComparison.OrdinalIgnoreCase)))
    {
        return;
    }

    context.Response.Headers["Access-Control-Allow-Origin"] = origin;
    context.Response.Headers["Vary"] = "Origin";
    context.Response.Headers["Access-Control-Allow-Credentials"] = "true";
    context.Response.Headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-CSRF-TOKEN";
    context.Response.Headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS";
}

bool TryGetBearerToken(HttpRequest request, out string token)
{
    token = string.Empty;
    var header = request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    token = header["Bearer ".Length..].Trim();
    return token.Length > 0;
}

string ComputeTokenKey(string token)
{
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
    return Convert.ToHexString(hash);
}

async Task<IntrospectionResponse?> IntrospectAsync(
    IHttpClientFactory httpClientFactory,
    GatewayOptions options,
    string token,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(options.AuthIntrospectionUrl) ||
        string.IsNullOrWhiteSpace(options.IntrospectionClientId) ||
        string.IsNullOrWhiteSpace(options.IntrospectionClientSecret))
    {
        return null;
    }

    var http = httpClientFactory.CreateClient("gateway");
    using var request = new HttpRequestMessage(HttpMethod.Post, options.AuthIntrospectionUrl);
    request.Content = new FormUrlEncodedContent(new Dictionary<string, string?>
    {
        ["token"] = token,
        ["token_type_hint"] = "access_token",
        ["client_id"] = options.IntrospectionClientId,
        ["client_secret"] = options.IntrospectionClientSecret
    });

    using var response = await http.SendAsync(request, ct);
    if (!response.IsSuccessStatusCode)
    {
        return null;
    }

    var stream = await response.Content.ReadAsStreamAsync(ct);
    return await JsonSerializer.DeserializeAsync<IntrospectionResponse>(stream, JsonOptions, ct);
}

async Task ProxyAsync(HttpContext context, IHttpClientFactory httpClientFactory, string upstream, string? gatewayToken)
{
    var targetUri = BuildTargetUri(context.Request, upstream);
    if (targetUri is null)
    {
        context.Response.StatusCode = StatusCodes.Status502BadGateway;
        await context.Response.WriteAsync("bad gateway");
        return;
    }

    var http = httpClientFactory.CreateClient("gateway");
    using var requestMessage = CreateProxyHttpRequest(context, targetUri, gatewayToken);
    using var responseMessage = await http.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

    context.Response.StatusCode = (int)responseMessage.StatusCode;
    CopyResponseHeaders(context, responseMessage);
    await responseMessage.Content.CopyToAsync(context.Response.Body);
}

Uri? BuildTargetUri(HttpRequest request, string upstream)
{
    if (string.IsNullOrWhiteSpace(upstream))
    {
        return null;
    }

    var baseUri = upstream.EndsWith('/')
        ? upstream.TrimEnd('/')
        : upstream;

    var path = request.Path.HasValue ? request.Path.Value : string.Empty;
    var query = request.QueryString.HasValue ? request.QueryString.Value : string.Empty;
    return new Uri(baseUri + path + query);
}

HttpRequestMessage CreateProxyHttpRequest(HttpContext context, Uri targetUri, string? gatewayToken)
{
    var requestMessage = new HttpRequestMessage(new HttpMethod(context.Request.Method), targetUri);

    var requestMethod = context.Request.Method;
    if (!HttpMethods.IsGet(requestMethod) &&
        !HttpMethods.IsHead(requestMethod) &&
        !HttpMethods.IsDelete(requestMethod) &&
        !HttpMethods.IsTrace(requestMethod))
    {
        requestMessage.Content = new StreamContent(context.Request.Body);
    }

    foreach (var header in context.Request.Headers)
    {
        if (HopByHopHeaders.Contains(header.Key))
        {
            continue;
        }

        if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
        {
            requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
        }
    }

    requestMessage.Headers.Host = targetUri.Authority;
    requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-For", context.Connection.RemoteIpAddress?.ToString());
    requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Proto", context.Request.Scheme);
    requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Host", context.Request.Host.Value);
    if (!string.IsNullOrWhiteSpace(gatewayToken))
    {
        requestMessage.Headers.Remove("X-Gateway-Token");
        requestMessage.Headers.TryAddWithoutValidation("X-Gateway-Token", gatewayToken);
    }

    return requestMessage;
}

void CopyResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
{
    foreach (var header in responseMessage.Headers)
    {
        context.Response.Headers[header.Key] = header.Value.ToArray();
    }

    foreach (var header in responseMessage.Content.Headers)
    {
        context.Response.Headers[header.Key] = header.Value.ToArray();
    }

    context.Response.Headers.Remove("transfer-encoding");
}
