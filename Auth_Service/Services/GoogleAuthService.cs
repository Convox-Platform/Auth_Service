using Auth_Service.Models;
using Dapper;
using Google.Apis.Auth;
using Grpc.Core;
using System.Data;
using IdGen;
using Google.Apis.Json;
using System.Text.Json;
namespace Auth_Service.Services
{
    public class GoogleAuthService:Google_auth.Google_authBase
    {
        private readonly IDbConnection _db;
        private readonly HttpClient _client;
        private readonly IdGenerator _generator;
        public override async Task<AuthResponse> LoginWithGoogle(Request request, ServerCallContext context)
        {
            try
            {
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
                    

                    await _db.ExecuteAsync(insertUserSql, new { Id = user.Id, user.Email }, transaction);

                    const string insertAccountSql = @"INSERT INTO OAuth_accounts (Id,Provider,User_id,Scope)
                        VALUES (@Id,@Provider, @User_id, @Scope);";

                    await _db.ExecuteAsync(insertAccountSql, new {Id = user.OAuth_account.Id, user.OAuth_account.Provider,
                        User_id = user.Id, user.OAuth_account.Scope }, transaction);
                    
                    transaction.Commit();
                }
                else
                {
                   user = await _db.QueryFirstOrDefaultAsync<User>(
                        "Select * From Users WHERE Id = @Id;",
                        new { Id = (long)account.User_id });

                    string sql = @"SELECT * FROM JWT_tokens WHERE User_id = @Id;";

                    var token = _db.QueryFirstOrDefault<Jwt_token>(sql, new { Id = user.Id });

                    if (token != null)
                    {
                        string sqlDelete = @"DELETE FROM JWT_tokens WHERE Id = @Id;";

                        await _db.ExecuteAsync(sqlDelete, new { Id = token.Id });
                    }
                   
                }

                var (AccessToken, RefreshToken) = JWTAuthService.JWTTokenGenerator(payload.Email,user.Id.ToString());

                return new AuthResponse { AccessToken = AccessToken, RefreshToken = RefreshToken };

            }
            catch (Exception ex)
            {
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
        }

        public GoogleAuthService(IDbConnection db, HttpClient client, IdGenerator generator)
        {
            _db = db;
            _client = client;
            _generator = generator;
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
