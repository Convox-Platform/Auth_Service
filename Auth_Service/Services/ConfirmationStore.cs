using Auth_Service.Models;
using StackExchange.Redis;
using Microsoft.AspNetCore.Http.Json;
using System.Text.Json;

using Grpc.Core;

public sealed class ConfirmationStore
{
    private readonly IDatabase _cache;

    public ConfirmationStore(IConnectionMultiplexer cache)
    {
        _cache = cache.GetDatabase();
    }
    private static JsonSerializerOptions JsonOption = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public async Task<string> Create(long id, string code)
    {
        var operationId = Guid.NewGuid().ToString();

        var confirmation = new PendingConfirmation(
            id,
            code,
            ""
            );

        var json = JsonSerializer.Serialize(confirmation,JsonOption);

        await _cache.StringSetAsync(
            operationId,
            json,
            TimeSpan.FromMinutes(5));

        return operationId;
    }

    public async Task<string> CreateWithEmail(string email, string code) {
        var operationId = Guid.NewGuid().ToString();

        var confirmation = new PendingConfirmation(
            default,
            code,
            email);

        var json = JsonSerializer.Serialize(confirmation,JsonOption);


        await _cache.StringSetAsync(
            operationId,
            json,
            TimeSpan.FromMinutes(5));

        return operationId;
    }

    public async Task<PendingConfirmation> TryGet(string operationId)
    {
        var json = await _cache.StringGetAsync(operationId);

        var confirmation = json.HasValue
            ? JsonSerializer.Deserialize<PendingConfirmation>(json,JsonOption)
            : null;
        if (confirmation == null)
            throw new RpcException(new Status(StatusCode.NotFound, "Confirmation not found"));

        return confirmation ;
    }

    public async Task Remove(string operationId)
    {
        await _cache.KeyDeleteAsync(operationId);
    }
}