namespace Auth_Service.Services;

public sealed record GoogleOAuthClientConfiguration(
    string ClientId,
    string? ClientSecret,
    IReadOnlySet<string> RedirectUris);

public sealed class GoogleOAuthClientRegistry
{
    private readonly IReadOnlyDictionary<string, GoogleOAuthClientConfiguration> _clientsByRedirectUri;

    public GoogleOAuthClientConfiguration WebClient { get; }

    private GoogleOAuthClientRegistry(
        GoogleOAuthClientConfiguration webClient,
        IReadOnlyDictionary<string, GoogleOAuthClientConfiguration> clientsByRedirectUri)
    {
        WebClient = webClient;
        _clientsByRedirectUri = clientsByRedirectUri;
    }

    public bool TryGetByRedirectUri(string redirectUri, out GoogleOAuthClientConfiguration client)
    {
        if (_clientsByRedirectUri.TryGetValue(redirectUri, out client!))
        {
            return true;
        }

        foreach (var entry in _clientsByRedirectUri)
        {
            if (IsAllowedLoopbackRedirect(entry.Key, redirectUri))
            {
                client = entry.Value;
                return true;
            }
        }

        client = null!;
        return false;
    }

    public static GoogleOAuthClientRegistry Create(
        string webClientId,
        string webClientSecret,
        string webRedirectUris,
        string? desktopClientId,
        string? desktopClientSecret,
        string? desktopRedirectUri)
    {
        var webClient = new GoogleOAuthClientConfiguration(
            webClientId,
            webClientSecret,
            ParseRedirectUris(webRedirectUris));

        var clients = new List<GoogleOAuthClientConfiguration> { webClient };
        var desktopConfigRequested = !string.IsNullOrWhiteSpace(desktopClientId)
            || !string.IsNullOrWhiteSpace(desktopClientSecret)
            || !string.IsNullOrWhiteSpace(desktopRedirectUri);

        if (desktopConfigRequested)
        {
            if (string.IsNullOrWhiteSpace(desktopClientId) || string.IsNullOrWhiteSpace(desktopRedirectUri))
            {
                throw new ArgumentException(
                    "GOOGLE_DESKTOP_CLIENT_ID and GOOGLE_DESKTOP_REDIRECT_URI must be configured together.");
            }

            clients.Add(new GoogleOAuthClientConfiguration(
                desktopClientId,
                string.IsNullOrWhiteSpace(desktopClientSecret) ? null : desktopClientSecret,
                ParseRedirectUris(desktopRedirectUri)));
        }

        var clientsByRedirectUri = new Dictionary<string, GoogleOAuthClientConfiguration>(StringComparer.Ordinal);
        foreach (var client in clients)
        {
            foreach (var redirectUri in client.RedirectUris)
            {
                if (!clientsByRedirectUri.TryAdd(redirectUri, client))
                {
                    throw new ArgumentException($"Duplicate Google redirect URI configured: {redirectUri}");
                }
            }
        }

        return new GoogleOAuthClientRegistry(webClient, clientsByRedirectUri);
    }

    private static IReadOnlySet<string> ParseRedirectUris(string value)
    {
        var redirectUris = value
            .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(uri => Uri.TryCreate(uri, UriKind.Absolute, out var parsed) && string.IsNullOrEmpty(parsed.Fragment))
            .ToHashSet(StringComparer.Ordinal);

        if (redirectUris.Count == 0)
        {
            throw new ArgumentException("At least one valid Google redirect URI must be configured.");
        }

        return redirectUris;
    }

    private static bool IsAllowedLoopbackRedirect(string configuredRedirectUri, string requestedRedirectUri)
    {
        if (!Uri.TryCreate(configuredRedirectUri, UriKind.Absolute, out var configured)
            || !Uri.TryCreate(requestedRedirectUri, UriKind.Absolute, out var requested))
        {
            return false;
        }

        return configured.Scheme == Uri.UriSchemeHttp
            && configured.Host == "127.0.0.1"
            && configured.IsDefaultPort
            && string.IsNullOrEmpty(configured.Query)
            && string.IsNullOrEmpty(configured.Fragment)
            && requested.Scheme == Uri.UriSchemeHttp
            && requested.Host == "127.0.0.1"
            && !requested.IsDefaultPort
            && requested.Port >= 1024
            && requested.AbsolutePath == configured.AbsolutePath
            && string.IsNullOrEmpty(requested.UserInfo)
            && string.IsNullOrEmpty(requested.Query)
            && string.IsNullOrEmpty(requested.Fragment);
    }
}
