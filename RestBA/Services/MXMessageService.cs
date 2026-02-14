using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RestBA.Models;
using RestBA.Options;

namespace RestBA.Services;

public class MXMessageService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ExternalApiOptions _apiOptions;
    private readonly CertificateOptions _certOptions;
    private readonly PollingOptions _pollingOptions;
    private readonly ILogger<MXMessageService> _logger;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private string? _accessToken;
    private DateTime _tokenExpiry = DateTime.MinValue;

    public MXMessageService(
        IHttpClientFactory httpClientFactory,
        IOptions<ExternalApiOptions> apiOptions,
        IOptions<CertificateOptions> certOptions,
        IOptions<PollingOptions> pollingOptions,
        ILogger<MXMessageService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _apiOptions = apiOptions.Value;
        _certOptions = certOptions.Value;
        _pollingOptions = pollingOptions.Value;
        _logger = logger;
    }

    private async Task<string> GetAccessToken()
    {
        if (!string.IsNullOrEmpty(_accessToken) && DateTime.UtcNow < _tokenExpiry.AddMinutes(-5))
        {
            return _accessToken;
        }

        await _tokenLock.WaitAsync();
        try
        {
            // Double-check after acquiring lock
            if (!string.IsNullOrEmpty(_accessToken) && DateTime.UtcNow < _tokenExpiry.AddMinutes(-5))
            {
                return _accessToken;
            }

            var client = _httpClientFactory.CreateClient("ExternalApi");
            var authUrl = _apiOptions.AuthUrl + "/token";
            var clientToken = GenerateClientToken();

            var requestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("username", _apiOptions.Username),
                new KeyValuePair<string, string>("password", _apiOptions.Password)
            });

            var request = new HttpRequestMessage(HttpMethod.Post, authUrl)
            {
                Content = requestContent
            };
            request.Headers.Add("Authorization", $"Bearer {clientToken}");
            request.Headers.Add("Accept", "application/json");

            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);

            _accessToken = tokenResponse.GetProperty("access_token").GetString();
            var expiresIn = tokenResponse.GetProperty("expires_in").GetInt32();
            _tokenExpiry = DateTime.UtcNow.AddSeconds(expiresIn);

            _logger.LogInformation("Access token obtained, expires at {Expiry}", _tokenExpiry);
            return _accessToken!;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private string GenerateClientToken()
    {
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            _certOptions.KeystorePath, _certOptions.KeystorePassword);

        var now = DateTimeOffset.UtcNow;
        var claims = new[]
        {
            new Claim("iss", _apiOptions.Username),
            new Claim("iat", now.ToUnixTimeSeconds().ToString()),
            new Claim("exp", now.AddMinutes(10).ToUnixTimeSeconds().ToString()),
            new Claim("asrv_type", "client"),
            new Claim("asrv_cert_iss", _certOptions.IssuerName),
            new Claim("asrv_cert_sn", _certOptions.SerialNumber)
        };

        var key = new X509SecurityKey(certificate);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            signingCredentials: credentials
        );

        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(token);
    }

    public async Task<bool> SendMessage(string traceReference, string messageType, string documentContent)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("ExternalApi");
            var accessToken = await GetAccessToken();
            var requestId = Guid.NewGuid().ToString();

            var url = $"{_apiOptions.BaseUrl}/input/{requestId}";

            var payload = new
            {
                traceReference,
                type = messageType,
                sender = _apiOptions.Username,
                receiver = _apiOptions.ReceiverCode,
                document = documentContent
            };

            var content = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json"
            );

            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = content
            };
            request.Headers.Add("Authorization", $"Bearer {accessToken}");
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("X-Timestamp", DateTime.UtcNow.ToString("o"));

            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Message sent successfully: {TraceRef}", traceReference);
                return true;
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to send message: {Status} - {Error}", response.StatusCode, error);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending message");
            return false;
        }
    }

    public async Task<List<MXMessage>> ReceiveMessages()
    {
        try
        {
            var client = _httpClientFactory.CreateClient("ExternalApi");
            var accessToken = await GetAccessToken();
            var requestId = Guid.NewGuid().ToString();

            var url = $"{_apiOptions.BaseUrl}/output/{requestId}";

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Authorization", $"Bearer {accessToken}");
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("X-Fetch-Timeout", _pollingOptions.FetchTimeoutMs.ToString());
            request.Headers.Add("X-Fetch-Size", _pollingOptions.FetchSize.ToString());
            request.Headers.Add("X-Timestamp", DateTime.UtcNow.ToString("o"));

            var response = await client.SendAsync(request);

            if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                return [];
            }

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Failed to receive messages: {Status} - {Error}", response.StatusCode, error);
                return [];
            }

            var responseBody = await response.Content.ReadAsStringAsync();
            var messages = JsonSerializer.Deserialize<List<MXMessage>>(responseBody, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            _logger.LogInformation("Received {Count} messages", messages?.Count ?? 0);
            return messages ?? [];
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error receiving messages");
            return [];
        }
    }
}
