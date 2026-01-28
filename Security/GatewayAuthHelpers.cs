using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Api.Gateway.Http;
using Microsoft.Extensions.Caching.Memory;

namespace Api.Gateway.Security;

public static class GatewayAuthHelpers
{
    public static async Task<bool> EnsureRootAsync(
        HttpContext context,
        GatewayOptions options,
        JsonSerializerOptions jsonOptions)
    {
        var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
        var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();

        CorsHelpers.ApplyCors(context, options.AllowedOrigins);
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

        var introspection = await IntrospectAsync(httpClientFactory, options, token, jsonOptions, context.RequestAborted);
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

    public static bool TryGetBearerToken(HttpRequest request, out string token)
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

    public static string ComputeTokenKey(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hash);
    }

    public static async Task<IntrospectionResponse?> IntrospectAsync(
        IHttpClientFactory httpClientFactory,
        GatewayOptions options,
        string token,
        JsonSerializerOptions jsonOptions,
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
        return await JsonSerializer.DeserializeAsync<IntrospectionResponse>(stream, jsonOptions, ct);
    }
}
