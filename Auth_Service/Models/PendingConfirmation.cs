namespace Auth_Service.Models
{
    public sealed record class PendingConfirmation(
        long UserId,
        string Code
        );
}
