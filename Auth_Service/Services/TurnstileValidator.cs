using System.Text.Json;
using System.Text.Json.Serialization;

namespace Auth_Service.Services;

public sealed class TurnstileValidator
{
    private const string SiteverifyUrl =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    private readonly HttpClient _httpClient;
    private readonly ILogger<TurnstileValidator> _logger;
    private readonly string _secretKey;
    private readonly HashSet<string> _expectedHostnames;

    public TurnstileValidator(
        HttpClient httpClient,
        ILogger<TurnstileValidator> logger,
        [FromKeyedServices("turnstile_secret_key")] string secretKey,
        [FromKeyedServices("turnstile_expected_hostnames")] string expectedHostnames)
    {
        _httpClient = httpClient;
        _logger = logger;
        _secretKey = secretKey;
        _expectedHostnames = expectedHostnames
            .Split(
                new[] { ',', ';' },
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public async Task<TurnstileValidationResult> ValidateAsync(
        string token,
        string expectedAction,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 2048)
        {
            return TurnstileValidationResult.Invalid("missing-or-invalid-token");
        }

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["secret"] = _secretKey,
            ["response"] = token,
            ["idempotency_key"] = Guid.NewGuid().ToString(),
        });

        try
        {
            using var response = await _httpClient.PostAsync(
                SiteverifyUrl,
                content,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Cloudflare Turnstile Siteverify returned HTTP {StatusCode}.",
                    (int)response.StatusCode);
                return TurnstileValidationResult.Unavailable();
            }

            await using var responseStream =
                await response.Content.ReadAsStreamAsync(cancellationToken);
            var result = await JsonSerializer.DeserializeAsync<TurnstileResponse>(
                responseStream,
                cancellationToken: cancellationToken);

            if (result is null)
            {
                return TurnstileValidationResult.Unavailable();
            }

            if (!result.Success)
            {
                _logger.LogInformation(
                    "Cloudflare Turnstile rejected a token. Error codes: {ErrorCodes}",
                    string.Join(",", result.ErrorCodes));
                return TurnstileValidationResult.Invalid(result.ErrorCodes);
            }

            if (!string.Equals(
                    result.Action,
                    expectedAction,
                    StringComparison.Ordinal))
            {
                _logger.LogWarning(
                    "Cloudflare Turnstile action mismatch. Expected {ExpectedAction}, got {Action}.",
                    expectedAction,
                    result.Action);
                return TurnstileValidationResult.Invalid("action-mismatch");
            }

            if (_expectedHostnames.Count > 0 &&
                !_expectedHostnames.Contains(result.Hostname))
            {
                _logger.LogWarning(
                    "Cloudflare Turnstile hostname {Hostname} is not allowed.",
                    result.Hostname);
                return TurnstileValidationResult.Invalid("hostname-mismatch");
            }

            return TurnstileValidationResult.Valid();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("Cloudflare Turnstile Siteverify timed out.");
            return TurnstileValidationResult.Unavailable();
        }
        catch (HttpRequestException exception)
        {
            _logger.LogWarning(
                exception,
                "Cloudflare Turnstile Siteverify could not be reached.");
            return TurnstileValidationResult.Unavailable();
        }
        catch (JsonException exception)
        {
            _logger.LogWarning(
                exception,
                "Cloudflare Turnstile Siteverify returned invalid JSON.");
            return TurnstileValidationResult.Unavailable();
        }
    }

    private sealed class TurnstileResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("hostname")]
        public string Hostname { get; init; } = "";

        [JsonPropertyName("action")]
        public string Action { get; init; } = "";

        [JsonPropertyName("error-codes")]
        public string[] ErrorCodes { get; init; } = [];
    }
}

public sealed record TurnstileValidationResult(
    bool IsValid,
    bool IsAvailable,
    IReadOnlyCollection<string> ErrorCodes)
{
    public static TurnstileValidationResult Valid() =>
        new(true, true, Array.Empty<string>());

    public static TurnstileValidationResult Invalid(params string[] errorCodes) =>
        new(false, true, errorCodes);

    public static TurnstileValidationResult Unavailable() =>
        new(false, false, Array.Empty<string>());
}
