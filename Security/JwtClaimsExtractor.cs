using System.Text;
using System.Text.Json;

namespace Api.Gateway.Security;

public static class JwtClaimsExtractor
{
    public static string? ExtractUserNameFromToken(string token)
    {
        var payload = TryDecodeJwtPayload(token);
        if (payload is null)
        {
            return null;
        }

        using var doc = JsonDocument.Parse(payload);
        if (!doc.RootElement.TryGetProperty("preferred_username", out var preferred))
        {
            if (!doc.RootElement.TryGetProperty("name", out preferred))
            {
                if (!doc.RootElement.TryGetProperty("email", out preferred))
                {
                    return null;
                }
            }
        }

        return preferred.ValueKind == JsonValueKind.String ? preferred.GetString() : null;
    }

    private static string? TryDecodeJwtPayload(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        var payload = parts[1];
        payload = payload.Replace('-', '+').Replace('_', '/');
        switch (payload.Length % 4)
        {
            case 2:
                payload += "==";
                break;
            case 3:
                payload += "=";
                break;
            case 0:
                break;
            default:
                return null;
        }

        try
        {
            var bytes = Convert.FromBase64String(payload);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }
}
