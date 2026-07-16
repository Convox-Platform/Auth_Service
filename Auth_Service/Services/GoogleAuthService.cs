using Auth_Service.Models;
using Dapper;
using Google.Apis.Auth;
using Grpc.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;
using IdGen;
using System.Data;
using System.Data.Common;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using User_Service;

namespace Auth_Service.Services
{
    public class GoogleAuthService : Google_auth.Google_authBase
    {
        private const string GoogleTokenEndpoint = "https://oauth2.googleapis.com/token";
        private const string OAuthStateHeader = "x-convox-oauth-state";
        private const string OAuthStateCookie = "convox_google_oauth_state";

        private static readonly HashSet<string> GoogleIssuers = new(StringComparer.Ordinal)
        {
            "accounts.google.com",
            "https://accounts.google.com"
        };

        private readonly DbConnection _db;
        private readonly HttpClient _client;
        private readonly IdGenerator _generator;
        private readonly string _userServiceUrl;
        private readonly string _jwtSecret;
        private readonly string _googleClientId;
        private readonly string _googleClientSecret;
        private readonly HashSet<string> _allowedOrigins;
        private readonly HashSet<string> _allowedRedirectUris;

        public GoogleAuthService(
            DbConnection db,
            HttpClient client,
            IdGenerator generator,
            [FromKeyedServices("user_service_url")] string userServiceUrl,
            [FromKeyedServices("secret_key")] string jwtSecret,
            [FromKeyedServices("google_client_id")] string googleClientId,
            [FromKeyedServices("google_client_secret")] string googleClientSecret,
            [FromKeyedServices("google_redirect_uris")] string redirectUris,
            [FromKeyedServices("allowed_origins")] string allowedOrigins)
        {
            _db = db;
            _client = client;
            _generator = generator;
            _userServiceUrl = userServiceUrl;
            _jwtSecret = jwtSecret;
            _googleClientId = googleClientId;
            _googleClientSecret = googleClientSecret;
            _allowedRedirectUris = ParseList(redirectUris);
            _allowedOrigins = ParseList(allowedOrigins, NormalizeOrigin);
        }

        public override async Task<AuthResponse> LoginWithGoogle(Request request, ServerCallContext context)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.IdToken))
                    throw RpcError(StatusCode.InvalidArgument, "Google ID token is required.");

                var payload = await ValidateGoogleIdTokenAsync(request.IdToken);
                return await LoginWithPayloadAsync(payload, payload.Scope, context.CancellationToken);
            }
            catch (RpcException)
            {
                throw;
            }
            catch (InvalidJwtException)
            {
                throw RpcError(StatusCode.Unauthenticated, "Google ID token is invalid or expired.");
            }
            catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
            {
                throw RpcError(StatusCode.Cancelled, "Google login was cancelled.");
            }
            catch (Exception)
            {
                throw RpcError(StatusCode.Internal, "Google login failed.");
            }
        }

        public override async Task<AuthResponse> LoginWithGoogleCode(GoogleCodeRequest request, ServerCallContext context)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Code))
                    throw RpcError(StatusCode.InvalidArgument, "Google authorization code is required.");

                var redirectUri = ValidateBrowserRequest(request, context);
                var tokenResponse = await CodeForTokenAsync(
                    request.Code,
                    redirectUri,
                    string.IsNullOrWhiteSpace(request.CodeVerifier) ? null : request.CodeVerifier,
                    context.CancellationToken);

                if (string.IsNullOrWhiteSpace(tokenResponse.IdToken))
                    throw RpcError(StatusCode.Unauthenticated, "Google did not return an ID token.");

                var payload = await ValidateGoogleIdTokenAsync(tokenResponse.IdToken);
                return await LoginWithPayloadAsync(payload, tokenResponse.Scope, context.CancellationToken);
            }
            catch (RpcException)
            {
                throw;
            }
            catch (InvalidJwtException)
            {
                throw RpcError(StatusCode.Unauthenticated, "Google ID token is invalid or expired.");
            }
            catch (HttpRequestException)
            {
                throw RpcError(StatusCode.Unavailable, "Google OAuth service is unavailable.");
            }
            catch (JsonException)
            {
                throw RpcError(StatusCode.Unavailable, "Google OAuth service returned an invalid response.");
            }
            catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
            {
                throw RpcError(StatusCode.Cancelled, "Google login was cancelled.");
            }
            catch (OperationCanceledException)
            {
                throw RpcError(StatusCode.DeadlineExceeded, "Google OAuth request timed out.");
            }
            catch (Exception)
            {
                throw RpcError(StatusCode.Internal, "Google login failed.");
            }
        }

        public Task<GoogleTokenResponse> CodeForTokenAsync(string code)
        {
            var redirectUri = _allowedRedirectUris.FirstOrDefault()
                ?? throw RpcError(StatusCode.FailedPrecondition, "No Google redirect URI is configured.");

            return CodeForTokenAsync(code, redirectUri, null, CancellationToken.None);
        }

        public async Task<GoogleTokenResponse> CodeForTokenAsync(
            string code,
            string redirectUri,
            string? codeVerifier,
            CancellationToken cancellationToken)
        {
            var requestData = new Dictionary<string, string>
            {
                ["code"] = code,
                ["client_id"] = _googleClientId,
                ["client_secret"] = _googleClientSecret,
                ["redirect_uri"] = redirectUri,
                ["grant_type"] = "authorization_code"
            };

            if (!string.IsNullOrWhiteSpace(codeVerifier))
                requestData["code_verifier"] = codeVerifier;

            using var content = new FormUrlEncodedContent(requestData);
            using var response = await _client.PostAsync(GoogleTokenEndpoint, content, cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
                throw CreateGoogleOAuthError(response.StatusCode, responseBody);

            return JsonSerializer.Deserialize<GoogleTokenResponse>(responseBody)
                ?? throw new JsonException("Empty Google token response.");
        }

        private async Task<GoogleJsonWebSignature.Payload> ValidateGoogleIdTokenAsync(string idToken)
        {
            var payload = await GoogleJsonWebSignature.ValidateAsync(
                idToken,
                new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { _googleClientId },
                    ExpirationTimeClockTolerance = TimeSpan.Zero
                });

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!GoogleIssuers.Contains(payload.Issuer)
                || !AudienceMatches(payload.Audience, _googleClientId)
                || payload.ExpirationTimeSeconds is null
                || payload.ExpirationTimeSeconds <= now)
            {
                throw new InvalidJwtException("Invalid Google ID token claims.");
            }

            if (string.IsNullOrWhiteSpace(payload.Subject)
                || string.IsNullOrWhiteSpace(payload.Email)
                || payload.EmailVerified != true)
            {
                throw new InvalidJwtException("Google account identity is incomplete or unverified.");
            }

            return payload;
        }

        private async Task<AuthResponse> LoginWithPayloadAsync(
            GoogleJsonWebSignature.Payload payload,
            string? scope,
            CancellationToken cancellationToken)
        {
            if (_db.State == ConnectionState.Closed)
                await _db.OpenAsync(cancellationToken);

            var account = await _db.QueryFirstOrDefaultAsync<OAuth_account>(
                "SELECT * FROM OAuth_accounts WHERE Provider = 'google' AND Id = @id",
                new { id = payload.Subject });

            User? user;
            if (account is null)
            {
                await using var transaction = await _db.BeginTransactionAsync(cancellationToken);
                var id = _generator.CreateId();
                user = new User { Id = id, Email = payload.Email! };

                await _db.ExecuteAsync(
                    "INSERT INTO Users (Id, Email) VALUES (@Id, @Email);",
                    new { user.Id, user.Email },
                    transaction);

                await _db.ExecuteAsync(
                    @"INSERT INTO OAuth_accounts (Id, Provider, User_id, Scope)
                      VALUES (@Id, 'google', @UserId, @Scope);",
                    new { Id = payload.Subject, UserId = user.Id, Scope = scope },
                    transaction);

                using var handler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler())
                {
                    HttpVersion = HttpVersion.Version11
                };
                using var channel = GrpcChannel.ForAddress(
                    _userServiceUrl,
                    new GrpcChannelOptions { HttpHandler = handler });
                var userClient = new UserService.UserServiceClient(channel);
                await userClient.CreateUserProfileAsync(
                    new CreateUserProfileRequest
                    {
                        UserId = id,
                        Img = payload.Picture ?? string.Empty,
                        Username = BuildUsername(payload),
                        DisplayName = payload.Name ?? string.Empty
                    },
                    cancellationToken: cancellationToken);

                await transaction.CommitAsync(cancellationToken);
            }
            else
            {
                user = await _db.QueryFirstOrDefaultAsync<User>(
                    "SELECT * FROM Users WHERE Id = @Id;",
                    new { Id = account.User_id });

                if (user is null)
                    throw RpcError(StatusCode.Internal, "Google account is not linked to a user.");
            }

            await _db.ExecuteAsync(
                "DELETE FROM JWT_tokens WHERE User_id = @Id;",
                new { user.Id });

            var (accessToken, refreshToken) = JWTAuthService.JWTTokenGenerator(
                user.Email!,
                user.Id,
                _jwtSecret);

            await _db.ExecuteAsync(
                @"INSERT INTO JWT_tokens (User_id, RefreshToken, Expires_at)
                  VALUES (@Id, @RefreshToken, @ExpiresAt);",
                new
                {
                    user.Id,
                    RefreshToken = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddDays(29)
                });

            return new AuthResponse { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        private string ValidateBrowserRequest(GoogleCodeRequest request, ServerCallContext context)
        {
            var httpContext = context.GetHttpContext();
            var origin = NormalizeOrigin(httpContext.Request.Headers.Origin.ToString());
            if (string.IsNullOrEmpty(origin) || !_allowedOrigins.Contains(origin))
                throw RpcError(StatusCode.PermissionDenied, "Request origin is not allowed.");

            var redirectUri = request.RedirectUri;
            if (string.IsNullOrWhiteSpace(redirectUri))
            {
                if (_allowedRedirectUris.Count != 1)
                    throw RpcError(StatusCode.InvalidArgument, "Redirect URI is required.");
                redirectUri = _allowedRedirectUris.Single();
            }

            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var parsedRedirect)
                || !string.IsNullOrEmpty(parsedRedirect.Fragment)
                || !_allowedRedirectUris.Contains(redirectUri))
            {
                throw RpcError(StatusCode.PermissionDenied, "Redirect URI is not allowed.");
            }

            var expectedState = context.RequestHeaders
                .FirstOrDefault(entry => entry.Key == OAuthStateHeader)?.Value;
            expectedState ??= httpContext.Request.Cookies[OAuthStateCookie];

            if (!IsValidState(request.State, expectedState))
                throw RpcError(StatusCode.PermissionDenied, "OAuth state validation failed.");

            if (httpContext.Request.Cookies.ContainsKey(OAuthStateCookie))
                httpContext.Response.Cookies.Delete(OAuthStateCookie);

            return redirectUri;
        }

        private static bool IsValidState(string actual, string? expected)
        {
            if (string.IsNullOrWhiteSpace(actual)
                || string.IsNullOrWhiteSpace(expected)
                || actual.Length < 32
                || actual.Length > 512
                || actual.Length != expected.Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(actual),
                Encoding.UTF8.GetBytes(expected));
        }

        private static RpcException CreateGoogleOAuthError(HttpStatusCode statusCode, string responseBody)
        {
            GoogleOAuthErrorResponse? googleError = null;
            try
            {
                googleError = JsonSerializer.Deserialize<GoogleOAuthErrorResponse>(responseBody);
            }
            catch (JsonException)
            {
                // Do not expose malformed upstream responses to clients.
            }

            return googleError?.Error switch
            {
                "invalid_request" => RpcError(StatusCode.InvalidArgument, "Google rejected the OAuth request."),
                "invalid_grant" => RpcError(StatusCode.Unauthenticated, "Google authorization code is invalid, expired, or already used."),
                "unauthorized_client" => RpcError(StatusCode.PermissionDenied, "Google OAuth client is not authorized."),
                "temporarily_unavailable" => RpcError(StatusCode.Unavailable, "Google OAuth service is temporarily unavailable."),
                _ when (int)statusCode >= 500 => RpcError(StatusCode.Unavailable, "Google OAuth service is unavailable."),
                _ => RpcError(StatusCode.Unauthenticated, "Google OAuth token exchange failed.")
            };
        }

        private static string BuildUsername(GoogleJsonWebSignature.Payload payload)
        {
            var givenName = payload.GivenName?.Trim().ToLowerInvariant();
            var familyName = payload.FamilyName?.Trim().ToLowerInvariant();
            var username = string.Join('_', new[] { givenName, familyName }.Where(value => !string.IsNullOrEmpty(value)));
            return string.IsNullOrEmpty(username) ? $"google_{payload.Subject}" : username;
        }

        private static bool AudienceMatches(object? audience, string expectedAudience)
        {
            return audience switch
            {
                string value => string.Equals(value, expectedAudience, StringComparison.Ordinal),
                JsonElement { ValueKind: JsonValueKind.String } value =>
                    string.Equals(value.GetString(), expectedAudience, StringComparison.Ordinal),
                JsonElement { ValueKind: JsonValueKind.Array } value =>
                    value.EnumerateArray().Any(item =>
                        item.ValueKind == JsonValueKind.String
                        && string.Equals(item.GetString(), expectedAudience, StringComparison.Ordinal)),
                IEnumerable<string> values => values.Contains(expectedAudience, StringComparer.Ordinal),
                _ => false
            };
        }

        private static HashSet<string> ParseList(string value, Func<string, string>? normalize = null)
        {
            normalize ??= item => item.Trim();
            return value
                .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(normalize)
                .Where(item => !string.IsNullOrEmpty(item))
                .ToHashSet(StringComparer.Ordinal);
        }

        private static string NormalizeOrigin(string origin)
        {
            if (!Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri))
                return string.Empty;
            return uri.GetLeftPart(UriPartial.Authority);
        }

        private static RpcException RpcError(StatusCode code, string message) =>
            new(new Status(code, message));
    }
}
