using Api.Gateway.Models;
using Microsoft.EntityFrameworkCore;

namespace Api.Gateway.Data;

public sealed class GatewayDbContext : DbContext
{
    public GatewayDbContext(DbContextOptions<GatewayDbContext> options)
        : base(options)
    {
    }

    public DbSet<GatewayEndpoint> GatewayEndpoints => Set<GatewayEndpoint>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<GatewayEndpoint>(entity =>
        {
            entity.ToTable("gateway_endpoints");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Method).HasColumnName("method").IsRequired();
            entity.Property(e => e.Path).HasColumnName("path").IsRequired();
            entity.Property(e => e.Scope).HasColumnName("scope").IsRequired();
            entity.Property(e => e.DisplayName).HasColumnName("display_name").IsRequired();
            entity.Property(e => e.NormalizedName).HasColumnName("normalized_name").IsRequired();
            entity.Property(e => e.Description).HasColumnName("description");
            entity.Property(e => e.UpdatedAt).HasColumnName("updated_at").IsRequired();

            entity.HasIndex(e => e.NormalizedName).IsUnique();
        });

        modelBuilder.Entity<RolePermission>(entity =>
        {
            entity.ToTable("gateway_role_permissions");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Role).HasColumnName("role").IsRequired();
            entity.Property(e => e.EndpointId).HasColumnName("endpoint_id").IsRequired();
            entity.Property(e => e.IsAllowed).HasColumnName("is_allowed").IsRequired();
            entity.Property(e => e.UpdatedAt).HasColumnName("updated_at").IsRequired();

            entity.HasIndex(e => new { e.Role, e.EndpointId }).IsUnique();
            entity.HasOne<GatewayEndpoint>()
                .WithMany()
                .HasForeignKey(e => e.EndpointId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
