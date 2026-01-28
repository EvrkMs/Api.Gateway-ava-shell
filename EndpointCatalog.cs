using Api.Gateway.Models;

namespace Api.Gateway;

public static class EndpointCatalog
{
    public static readonly IReadOnlyCollection<GatewayEndpoint> All = new[]
    {
        // Safe.Service
        Make("POST", "/api/safe/changes", "safe", "Создать изменение кассы", "Создание записи изменения кассы"),
        Make("GET", "/api/safe/changes/{id}", "safe", "Получить изменение по ID", "Детальная информация об изменении кассы"),
        Make("GET", "/api/safe/changes", "safe", "Список изменений", "Список изменений кассы"),
        Make("GET", "/api/safe/balance", "safe", "Баланс кассы", "Текущий баланс кассы"),
        Make("POST", "/api/safe/changes/{id}/reverse", "safe", "Отменить изменение", "Реверс изменения кассы"),

        // Auth.Service (admin API)
        Make("GET", "/api/cruduser", "auth", "Список сотрудников", "Получить список сотрудников"),
        Make("GET", "/api/cruduser/{id}", "auth", "Сотрудник по ID", "Получить сотрудника по идентификатору"),
        Make("POST", "/api/cruduser", "auth", "Создать сотрудника", "Создание сотрудника"),
        Make("PUT", "/api/cruduser/{id}", "auth", "Обновить сотрудника", "Обновление сотрудника"),
        Make("POST", "/api/cruduser/{id}/password", "auth", "Сбросить пароль", "Сброс пароля сотрудника"),

        Make("GET", "/api/cruduser/roles", "auth", "Список ролей", "Получить список ролей"),
        Make("POST", "/api/cruduser/roles", "auth", "Создать роль", "Создание роли"),
        Make("PUT", "/api/cruduser/roles/{id}", "auth", "Обновить роль", "Обновление роли"),
        Make("DELETE", "/api/cruduser/roles/{id}", "auth", "Удалить роль", "Удаление роли"),

        Make("GET", "/api/sessions", "auth", "Список сессий", "Получить список активных сессий пользователя"),
        Make("GET", "/api/sessions/current", "auth", "Текущая сессия", "Получить текущую сессию"),
        Make("POST", "/api/sessions/{id}/revoke", "auth", "Отозвать сессию", "Отозвать сессию по ID"),
        Make("POST", "/api/sessions/revoke-all", "auth", "Отозвать все сессии", "Отозвать все сессии кроме текущей"),

        Make("GET", "/api/role-scopes", "auth", "Список ролей/скоупов", "Получить назначенные роли/скоупы"),
        Make("PUT", "/api/role-scopes", "auth", "Обновить роли/скоупы", "Обновить назначения ролей и скоупов"),
        Make("DELETE", "/api/role-scopes/{role}/{scope}", "auth", "Удалить роль/скоуп", "Удалить назначение роли и скоупа"),

        Make("GET", "/api/telegram/me", "auth", "Telegram профиль", "Получить Telegram профиль"),
        Make("POST", "/api/telegram/bind", "auth", "Привязать Telegram", "Привязка Telegram"),
        Make("POST", "/api/telegram/unbind", "auth", "Отвязать Telegram", "Отвязка Telegram")
    };

    private static GatewayEndpoint Make(string method, string path, string scope, string displayName, string? description)
    {
        var normalizedPath = NormalizePath(path);
        return new GatewayEndpoint
        {
            Id = Guid.NewGuid(),
            Method = method.ToUpperInvariant(),
            Path = normalizedPath,
            Scope = scope.ToLowerInvariant(),
            DisplayName = displayName,
            NormalizedName = $"{method.ToUpperInvariant()} {normalizedPath}",
            Description = description,
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }

    private static string NormalizePath(string path)
    {
        var value = path.Trim();
        if (!value.StartsWith('/'))
        {
            value = "/" + value;
        }

        if (value.Length > 1 && value.EndsWith('/'))
        {
            value = value.TrimEnd('/');
        }

        return value;
    }
}
