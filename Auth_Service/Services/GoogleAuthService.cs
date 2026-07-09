using Auth_Service.Models;
using Dapper;
using Google.Apis.Auth;
using Grpc.Core;
using System.Data;
using IdGen;
using Google.Apis.Json;
using System.Text.Json;
using System.Data.Common;
using System.Net.Http;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;
using User_Service;
using System.Net;
namespace Auth_Service.Services
{
    public class GoogleAuthService:Google_auth.Google_authBase
    {
        private readonly DbConnection _db;
        private readonly HttpClient _client;
        private readonly IdGenerator _generator;
        private readonly string _user_service_url;
        private readonly string _secret;
        public override async Task<AuthResponse> LoginWithGoogle(Request request, ServerCallContext context)
        {
            try
            {

                var handler = new GrpcWebHandler(GrpcWebMode.GrpcWeb,new SocketsHttpHandler());

                var channel = GrpcChannel.ForAddress(_user_service_url, new GrpcChannelOptions { HttpHandler = handler });
                var client = new UserService.UserServiceClient(channel);

                var settings = new GoogleJsonWebSignature.ValidationSettings()
                {
                    Audience = new[] { Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") }
                };
                Console.WriteLine(request.IdToken);
                var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);

                if (_db.State == ConnectionState.Closed)
                    _db.Open();
                

                OAuth_account? account = await _db.QueryFirstOrDefaultAsync<OAuth_account>(
                    "SELECT * FROM OAuth_accounts WHERE Provider = 'google' AND Id = @id",
                    new { id = payload.Subject });
                User? user;
                
                
                
                if (account == null)
                {
                    var transaction = _db.BeginTransaction();

                    long id = _generator.CreateId();
                    
                    const string insertUserSql = @"INSERT INTO Users (Id, Email) 
                                                    VALUES (@Id, @Email);";

                    user = new User
                    {
                        Id = id,
                        Email = payload.Email,
                        OAuth_account = new OAuth_account
                        {
                            Provider = "Google",
                            Id = payload.Subject,
                            Scope = payload.Scope
                        }
                    };

                    var userServiceRequest = new CreateUserProfileRequest{
                        UserId = id,
                        Img = payload.Picture,
                        Username = $"{payload.GivenName?.ToLower()}_{payload.FamilyName?.ToLower()}",
                        DisplayName = $"{payload.GivenName} {payload.FamilyName}"
                    };

                    await _db.ExecuteAsync(insertUserSql, new { Id = user.Id, user.Email }, transaction);

                    const string insertAccountSql = @"INSERT INTO OAuth_accounts (Id,Provider,User_id,Scope)
                        VALUES (@Id,@Provider, @User_id, @Scope);";

                    await _db.ExecuteAsync(insertAccountSql, new {Id = user.OAuth_account.Id, user.OAuth_account.Provider,
                        User_id = user.Id, user.OAuth_account.Scope }, transaction);
                    
                    var resp = await client.CreateUserProfileAsync(userServiceRequest);

                    Console.WriteLine("resp from another service  " + resp.Status);
                    transaction.Commit();
                }
                else
                {
                   user = await _db.QueryFirstOrDefaultAsync<User>(
                        "Select * From Users WHERE Id = @Id;",
                        new { Id = (long)account.User_id });

                    string sql = @"SELECT * FROM JWT_tokens WHERE User_Id = @Id;";

                    var token = _db.QueryFirstOrDefault<Jwt_token>(sql, new { Id = user.Id });

                    string sqlDelete = @"DELETE FROM JWT_tokens WHERE Id = @Id;";

                    await _db.ExecuteAsync(sqlDelete, new { Id = token.Id });
                   
                }

                var (AccessToken, RefreshToken) = JWTAuthService.JWTTokenGenerator(payload.Email,user.Id.ToString(), _secret);

                var sql2 = @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at) VALUES (@id, @token, @expires_at)";
                await _db.ExecuteAsync(sql2, new { id = user.Id, token = RefreshToken, expires_at = DateTime.UtcNow.AddDays(29) });
                Console.WriteLine("Token: " + AccessToken);

                await channel.ShutdownAsync();
                return new AuthResponse { AccessToken = AccessToken, RefreshToken = RefreshToken };

            }
            catch (Exception ex)
            {
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
        }

        public GoogleAuthService(DbConnection db, HttpClient client, IdGenerator generator, [FromKeyedServices("user_service_url")] string url,
            [FromKeyedServices("secret_key")] string secret)
        {
            _db = db;
            _client = client;
            _generator = generator;
            _user_service_url = url;
            _secret = secret;
        }
        
        public async Task<GoogleTokenResponse> CodeForTokenAsync(string code)
        {
            const string googleTokenEndpoint = "https://oauth2.googleapis.com/token";
            
            var requestData = new Dictionary<string, string>
            {
                { "code", code },
                { "client_id", Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") },
                { "client_secret", Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") },
                { "redirect_uri", Environment.GetEnvironmentVariable("REDIRECT_URI") },
                { "grant_type", "authorization_code" }
            };

            var context = new FormUrlEncodedContent(requestData);

            var resp = await _client.PostAsync(googleTokenEndpoint, context);
            if (!resp.IsSuccessStatusCode)
            {
                var error = await resp.Content.ReadAsStringAsync();
                throw new RpcException(new Status(StatusCode.Internal, $"Error getting token {error}"));
            }

            var jsonResponse = await resp.Content.ReadAsStringAsync();

            return JsonSerializer.Deserialize<GoogleTokenResponse>(jsonResponse);
        }
        
    }

   
}
