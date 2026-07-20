using Dapper.Contrib.Extensions;
using System.ComponentModel.DataAnnotations;

namespace Auth_Service.Models
{
    public class User
    {
        [ExplicitKey]
        public long Id { get; set; }

        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        public string? PasswordHash { get; set; }

        public DateTime? DeletedAt { get; set; }

        public List<Jwt_token>? Jwt_tokens { get; set; } = new List<Jwt_token>(); // ?>

        public OAuth_account? OAuth_account { get; set; }
    }
}
