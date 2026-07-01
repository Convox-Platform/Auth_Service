namespace Auth_Service.Models
{
    public class Jwt_token
    {
        public int Id { get; set; }
        public string? RefreshToken { get; set; }

        public DateTime Expires_at { get; set; } 
        public long? User_id { get; set; } 
        public User? User { get; set; }
    }
}
