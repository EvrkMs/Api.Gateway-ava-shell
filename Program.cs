using System.Net;
using System.Text.Json;
using Api.Gateway;
using Api.Gateway.Data;
using Api.Gateway.Endpoints;
using Api.Gateway.Security;
using Api.Gateway.Services;
using Api.Gateway.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);

builder.Services.AddMemoryCache();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("gateway-admin", new OpenApiInfo
    {
        Title = "Gateway Admin API",
        Version = "v1"
    });
    options.DocInclusionPredicate((docName, apiDesc) =>
    {
        if (!string.Equals(docName, "gateway-admin", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var path = apiDesc.RelativePath ?? string.Empty;
        return path.StartsWith("api/gateway", StringComparison.OrdinalIgnoreCase);
    });
});
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

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/gateway/swagger", StringComparison.OrdinalIgnoreCase))
    {
        var options = context.RequestServices
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<GatewayOptions>>()
            .Value;

        if (!await GatewayAuthHelpers.EnsureRootAsync(context, options, jsonOptions))
        {
            return;
        }
    }

    await next();
});

app.MapSwagger("api/gateway/swagger/{documentName}/swagger.json");
app.MapHealthEndpoints();
app.MapContractEndpoints();
app.MapGatewayAdminEndpoints(jsonOptions);
app.MapProxyEndpoint(jsonOptions);

app.Run();
