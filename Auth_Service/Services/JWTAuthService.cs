using Auth_Service.Models;
using Dapper;
using DotNetEnv;
using Grpc.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;
using IdGen;
using Microsoft.IdentityModel.Tokens;
using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User_Service;
using static BCrypt.Net.BCrypt;
namespace Auth_Service.Services
{
    public class JWTAuthService:JWT_Auth.JWT_AuthBase
    {
        private readonly DbConnection _db;
        private readonly IdGenerator _generator;
        private readonly string _user_service_url;
        private readonly string _secret;
        private readonly TurnstileValidator _turnstileValidator;
        private readonly bool _botCheckEnabled;

        public override async Task<Tokens> Registration(AuthData request, ServerCallContext context)
        {
            //await ValidateTurnstileAsync(
            //    request.TurnstileToken,
            //    "register",
            //    context.CancellationToken);

            //if (!request.AcceptedTerms)
            //{
            //    throw new RpcException(new Status(
            //        StatusCode.InvalidArgument,
            //        "Terms of Service and Privacy Policy must be accepted."));
            //}

            var handler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler())
            {
                HttpVersion = System.Net.HttpVersion.Version11
            };

            var channel = GrpcChannel.ForAddress(_user_service_url, new GrpcChannelOptions { HttpHandler = handler });
            var client = new UserService.UserServiceClient(channel);

            string sql = @"SELECT * FROM Users WHERE LOWER(Email) = LOWER(@email)";

            var user = await _db.QueryFirstOrDefaultAsync<User>(sql, new { email = request.Email});

            if (user != null)
            {
                throw new RpcException(new Status(StatusCode.AlreadyExists, "User already exists"));
            }

            long id = _generator.CreateId();

            var passwordHash = HashPassword(request.Password);

            string sql2 = @"INSERT INTO Users (Id, Email, PasswordHash) VALUES (@id, @email, @password)";
            await _db.ExecuteAsync(sql2, new { id = id, email = request.Email, password = passwordHash });

            var username = string.IsNullOrWhiteSpace(request.Username)
                ? request.Email.Split('@')[0]
                : request.Username.Trim();
            var displayName = string.IsNullOrWhiteSpace(request.DisplayName)
                ? username
                : request.DisplayName.Trim();

            var userprofile  = await client.CreateUserProfileAsync(new CreateUserProfileRequest {
                UserId = id,
                Username = username,
                DisplayName = displayName,
            });

            if (userprofile == null)
            {
                throw new RpcException(new Status(StatusCode.NotFound, "User could not be created"));
            }

            var (AccessToken, RefreshToken) = JWTTokenGenerator(request.Email, id,_secret);

            if (!string.IsNullOrWhiteSpace(request.BirthDate))
            {
                var headers = new Metadata
                {
                    { "Authorization", $"Bearer {AccessToken}" },
                };
                await client.UpdateUserProfileAsync(
                    new UpdateUserProfileRequest
                    {
                        UserId = id,
                        Username = userprofile.Username,
                        DisplayName = userprofile.DisplayName,
                        BirthDate = request.BirthDate,
                        Status = "new user",
                    },
                    headers,
                    cancellationToken: context.CancellationToken);
            }

            string sql3 = @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at) VALUES (@id, @token, @expires_at)";
            await _db.ExecuteAsync(sql3, new { id, token = RefreshToken, expires_at = DateTime.UtcNow.AddDays(29) });

            await channel.ShutdownAsync();
            return new Tokens { AccessToken = AccessToken, RefreshToken = RefreshToken };

        }

        public override async Task<Tokens> Login(AuthData request, ServerCallContext context)
        {
            await ValidateTurnstileAsync(
                request.TurnstileToken,
                "login",
                context.CancellationToken);

            string sql = @"SELECT * FROM Users WHERE LOWER(Email) = LOWER(@email)";

            var user = await _db.QueryFirstOrDefaultAsync<User>(sql, new { email = request.Email });
            if (user == null)
            {
                throw new RpcException(new Status(StatusCode.NotFound, "User not found"));
            }

            if (user.DeletedAt != null)
            {
                string sqlUpdate = @"UPDATE Users SET Deleted_At = NULL WHERE Id = @id";
                await _db.ExecuteAsync(sqlUpdate, new { id = user.Id });
            }

            if (!Verify(request.Password, user.PasswordHash))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Wrong password"));
            }

            var (AccessToken, RefreshToken) = JWTTokenGenerator(request.Email, user.Id,_secret);

            var sql2 = @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at) VALUES (@id, @token, @expires_at)";
            await _db.ExecuteAsync(sql2, new { id = user.Id, token = RefreshToken, expires_at = DateTime.UtcNow.AddDays(29) });

            return new Tokens { AccessToken = AccessToken, RefreshToken = RefreshToken };

        }

        public override async Task<Tokens> RefreshToken(Tokens request, ServerCallContext context)
        {
            string sqlDelete;
            string selectSql = @"
            SELECT t.*, u.Email 
            FROM JWT_tokens t
            JOIN Users u ON t.User_id = u.Id
            WHERE t.refreshtoken = @token";

            var tokenRecord = _db.QueryFirstOrDefault <dynamic>(selectSql, new { token = request.RefreshToken });

            if (tokenRecord == null)
            {
                throw new RpcException(new Status(StatusCode.NotFound, "Token not found"));
            }

            Console.WriteLine("Token Record: " + tokenRecord.refreshtoken);
            
            if (tokenRecord.expires_at < DateTime.UtcNow)
            {
                sqlDelete = @"DELETE FROM JWT_tokens WHERE refreshtoken = @token";
                await _db.ExecuteAsync(sqlDelete, new { token = request.RefreshToken });

                throw new RpcException(new Status(StatusCode.Unauthenticated, "Token expired"));
            }

            sqlDelete = @"DELETE FROM JWT_tokens WHERE refreshtoken = @token";
            await _db.ExecuteAsync(sqlDelete, new { token = request.RefreshToken });

            string email = tokenRecord.email;
            long userId =Convert.ToInt64(tokenRecord.user_id);
            var (AccessToken, RefreshToken) = JWTTokenGenerator(email, userId,_secret);

            string sql2 = @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at) VALUES (@id, @token, @expires_at)";
            await _db.ExecuteAsync(sql2, new { id = userId, token = RefreshToken, expires_at = DateTime.UtcNow.AddDays(29) });

            return new Tokens { AccessToken = AccessToken, RefreshToken = RefreshToken };

        }


        public JWTAuthService(DbConnection db, IdGenerator generator,
            [FromKeyedServices("user_service_url")] string url,
            [FromKeyedServices("secret_key")] string secret,
            [FromKeyedServices("enable_bot_check")] string botCheckEnabled,
            TurnstileValidator turnstileValidator)
        {
            _db = db;
            _generator = generator;
            _user_service_url = url;
            _secret = secret;
            _botCheckEnabled = bool.Parse(botCheckEnabled);
            _turnstileValidator = turnstileValidator;
        }

        private async Task ValidateTurnstileAsync(
            string token,
            string action,
            CancellationToken cancellationToken)
        {
            if (!_botCheckEnabled)
            {
                return;
            }

            var result = await _turnstileValidator.ValidateAsync(
                token,
                action,
                cancellationToken);

            if (!result.IsAvailable)
            {
                throw new RpcException(new Status(
                    StatusCode.Unavailable,
                    "Human verification is temporarily unavailable."));
            }

            if (!result.IsValid)
            {
                throw new RpcException(new Status(
                    StatusCode.FailedPrecondition,
                    "Human verification failed."));
            }
        }

        public static (string AccessToken, string RefreshToken) JWTTokenGenerator(string email, long userId, string secret )
        {
            

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secret);

            var tokenDescriptior = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                    new Claim(ClaimTypes.Email, email),
                    new Claim(ClaimTypes.NameIdentifier, userId.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                )
            };

            var token = tokenHandler.CreateToken(tokenDescriptior);
            var AccessToken = tokenHandler.WriteToken(token);

            var randBytes = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randBytes);
            }
            var RefreshToken = Convert.ToBase64String(randBytes);

            return (AccessToken, RefreshToken);
        }
    }
}
