using System.Text.Json;
using Api.Gateway.Stores;
using Microsoft.Extensions.Options;

namespace Api.Gateway.Services;

public sealed class RoleScopeSyncService : BackgroundService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<GatewayOptions> _options;
    private readonly RoleScopeStore _roleScopeStore;

    public RoleScopeSyncService(
        IHttpClientFactory httpClientFactory,
        IOptions<GatewayOptions> options,
        RoleScopeStore roleScopeStore)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
        _roleScopeStore = roleScopeStore;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await SyncOnceAsync(stoppingToken);
            var delay = TimeSpan.FromSeconds(Math.Max(1, _options.Value.PolicyRefreshSeconds));
            await Task.Delay(delay, stoppingToken);
        }
    }

    private async Task SyncOnceAsync(CancellationToken ct)
    {
        var options = _options.Value;
        if (string.IsNullOrWhiteSpace(options.RoleScopesSyncUrl) || string.IsNullOrWhiteSpace(options.GatewaySyncToken))
        {
            return;
        }

        var http = _httpClientFactory.CreateClient("gateway");
        using var request = new HttpRequestMessage(HttpMethod.Get, options.RoleScopesSyncUrl);
        request.Headers.TryAddWithoutValidation("X-Gateway-Token", options.GatewaySyncToken);

        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            return;
        }

        var stream = await response.Content.ReadAsStreamAsync(ct);
        var scopes = await JsonSerializer.DeserializeAsync<List<RoleScopeDto>>(stream, JsonOptions, ct);
        if (scopes is null)
        {
            return;
        }

        _roleScopeStore.Update(scopes);
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}
