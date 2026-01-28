namespace Api.Gateway.Models;

public sealed class RolePermission
{
    public Guid Id { get; set; }
    public string Role { get; set; } = string.Empty;
    public Guid EndpointId { get; set; }
    public bool IsAllowed { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
