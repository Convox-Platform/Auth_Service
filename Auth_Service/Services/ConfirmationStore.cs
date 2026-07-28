using Microsoft.Extensions.Caching.Memory;
using Auth_Service.Models;

public sealed class ConfirmationStore
{
    private readonly IMemoryCache _cache;

    public ConfirmationStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public string Create(long id, string code)
    {
        var operationId = Guid.NewGuid().ToString();

        var confirmation = new PendingConfirmation(
            id,
            code,
            ""
            );

        _cache.Set(
            operationId,
            confirmation,
            DateTimeOffset.UtcNow.AddMinutes(5));

        return operationId;
    }

    public string CreateWithEmail(string email, string code) {
        var operationId = Guid.NewGuid().ToString();

        var confirmation = new PendingConfirmation(
            default,
            code,
            email);


        _cache.Set(
            operationId,
            confirmation,
            DateTimeOffset.UtcNow.AddMinutes(5));

        return operationId;
    }

    public bool TryGet(
        string operationId,
        out PendingConfirmation? confirmation)
    {
        return _cache.TryGetValue(operationId, out confirmation);
    }

    public void Remove(string operationId)
    {
        _cache.Remove(operationId);
    }
}