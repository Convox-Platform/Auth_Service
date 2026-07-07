using Auth_Service.Models;
using Dapper;
using DotNetEnv;
using Grpc.Core;
using IdGen;
using Microsoft.IdentityModel.Tokens;
using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static BCrypt.Net.BCrypt;
namespace Auth_Service.Services
{
    public class JWTAuthService:JWT_Auth.JWT_AuthBase
    {
        private readonly DbConnection _db;
        private readonly IdGenerator _generator;

        public override async Task<Tokens> Registration(AuthData request, ServerCallContext context)
        {
            string sql = @"SELECT * FROM Users WHERE Email = @email";

            var user = _db.QueryFirstOrDefault<User>(sql, new { email = request.Email});

            if (user != null)
            {
                throw new RpcException(new Status(StatusCode.AlreadyExists, "User already exists"));
            }

            long id = _generator.CreateId();

            var passwordHash = HashPassword(request.Password);

            string sql2 = @"INSERT INTO Users (Id, Email, PasswordHash) VALUES (@id, @email, @password)";
            await _db.ExecuteAsync(sql2, new { id = id, email = request.Email, password = passwordHash });

            var (AccessToken, RefreshToken) = JWTTokenGenerator(request.Email, id.ToString());

            string sql3 = @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at) VALUES (@id, @token, @expires_at)";
            await _db.ExecuteAsync(sql3, new { id, token = RefreshToken, expires_at = DateTime.UtcNow.AddDays(29) });


            return new Tokens { AccessToken = AccessToken, RefreshToken = RefreshToken };

        }

        public override async Task<Tokens> Login(AuthData request, ServerCallContext context)
        {
           string sql = @"SELECT * FROM Users WHERE Email = @email";

            var user = _db.QueryFirstOrDefault<User>(sql, new { email = request.Email });
            if (user == null)
            {
                throw new RpcException(new Status(StatusCode.NotFound, "User not found"));
            }

            if (!Verify(request.Password, user.PasswordHash))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Wrong password"));
            }

            var (AccessToken, RefreshToken) = JWTTokenGenerator(request.Email, user.Id.ToString());

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
            WHERE t.RefreshToken = @token";

            var tokenRecord = _db.QueryFirstOrDefault <dynamic>(selectSql, new { token = request.RefreshToken });
            Console.WriteLine("Token Record: " + tokenRecord.RefreshToken);
            if (tokenRecord == null)
            {
                throw new RpcException(new Status(StatusCode.NotFound, "Token not found"));
            }

            if (tokenRecord.Expires_at < DateTime.UtcNow)
            {
                sqlDelete = @"DELETE FROM JWT_tokens WHERE RefreshToken = @token";
                await _db.ExecuteAsync(sqlDelete, new { token = request.RefreshToken });

                throw new RpcException(new Status(StatusCode.Unauthenticated, "Token expired"));
            }

            sqlDelete = @"DELETE FROM JWT_tokens WHERE RefreshToken = @token";
            await _db.ExecuteAsync(sqlDelete, new { token = request.RefreshToken });

            string email = tokenRecord.Email;
            string userId = tokenRecord.User_id;
            var (AccessToken, RefreshToken) = JWTTokenGenerator(email, userId);

            string sql2 = @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at) VALUES (@id, @token, @expires_at)";
            await _db.ExecuteAsync(sql2, new { id = userId, token = RefreshToken, expires_at = DateTime.UtcNow.AddDays(29) });

            return new Tokens { AccessToken = AccessToken, RefreshToken = RefreshToken };

        }


        public JWTAuthService(DbConnection db, IdGenerator generator)
        {
            _db = db;
            _generator = generator;
        }

        public static (string AccessToken, string RefreshToken) JWTTokenGenerator(string email, string userId)
        {
            Env.Load();
            var secret = Environment.GetEnvironmentVariable("JWT_SECRET");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secret);

            var tokenDescriptior = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    // sub = userId: gateway читає саме claims.Subject (sub) і парсить як id.
                    new Claim(JwtRegisteredClaimNames.Sub, userId),
                    new Claim(ClaimTypes.Email, email),
                    new Claim(ClaimTypes.NameIdentifier, userId)
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
