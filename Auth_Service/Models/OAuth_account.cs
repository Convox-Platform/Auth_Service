using System.ComponentModel.DataAnnotations;

namespace Auth_Service.Models
{
    public class OAuth_account
    {
        [Key]
        public string Id { get; set; }
        public string? Provider { get; set; }
        public string? Access_token { get; set; }
        public string? Refresh_token { get; set; }
        public DateTime? Expires_at { get; set; }

        public string? Scope { get; set; }

        public long? User_id { get; set; }
        public User? User { get; set; }
    }
}
