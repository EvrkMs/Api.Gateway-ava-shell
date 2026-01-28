namespace Api.Gateway.Models;

public sealed record GatewayPermissionRequest(
    string Role,
    Guid EndpointId,
    bool IsAllowed);

public sealed record GatewayPermissionResponse(
    Guid Id,
    string Role,
    Guid EndpointId,
    bool IsAllowed,
    DateTimeOffset UpdatedAt);
