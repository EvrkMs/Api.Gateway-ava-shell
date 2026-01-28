namespace Api.Gateway.Http;

public static class ProxyHelpers
{
    private static readonly HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
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

    public static async Task ProxyAsync(
        HttpContext context,
        IHttpClientFactory httpClientFactory,
        string upstream,
        string? gatewayToken,
        string? userId,
        string? userName)
    {
        var targetUri = BuildTargetUri(context.Request, upstream);
        if (targetUri is null)
        {
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            await context.Response.WriteAsync("bad gateway");
            return;
        }

        var http = httpClientFactory.CreateClient("gateway");
        using var requestMessage = CreateProxyHttpRequest(context, targetUri, gatewayToken, userId, userName);
        using var responseMessage = await http.SendAsync(
            requestMessage,
            HttpCompletionOption.ResponseHeadersRead,
            context.RequestAborted);

        context.Response.StatusCode = (int)responseMessage.StatusCode;
        CopyResponseHeaders(context, responseMessage);
        await responseMessage.Content.CopyToAsync(context.Response.Body);
    }

    private static Uri? BuildTargetUri(HttpRequest request, string upstream)
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

    private static HttpRequestMessage CreateProxyHttpRequest(
        HttpContext context,
        Uri targetUri,
        string? gatewayToken,
        string? userId,
        string? userName)
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
        if (!string.IsNullOrWhiteSpace(userId))
        {
            requestMessage.Headers.Remove("X-User-Id");
            requestMessage.Headers.TryAddWithoutValidation("X-User-Id", userId);
        }
        if (!string.IsNullOrWhiteSpace(userName))
        {
            requestMessage.Headers.Remove("X-User-Name");
            requestMessage.Headers.TryAddWithoutValidation("X-User-Name", userName);
        }
        if (!string.IsNullOrWhiteSpace(gatewayToken))
        {
            requestMessage.Headers.Remove("X-Gateway-Token");
            requestMessage.Headers.TryAddWithoutValidation("X-Gateway-Token", gatewayToken);
        }

        return requestMessage;
    }

    private static void CopyResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
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
}
