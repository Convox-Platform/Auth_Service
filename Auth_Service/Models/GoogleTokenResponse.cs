namespace Auth_Service.Models
{
    public class GoogleTokenResponse
    {
        public string? access_token { get; set; }
        public string? refresh_token { get; set; }
        public string? Id_token { get; set; }

        public int expires_in { get; set; }
        public string? scope { get; set; }
    }
}
