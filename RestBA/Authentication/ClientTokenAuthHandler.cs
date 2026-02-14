using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using Microsoft.IdentityModel.Tokens;
using RestBA.Options;

namespace RestBA.Authentication;

public class ClientTokenAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly CertificateOptions _certOptions;

    public ClientTokenAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IOptions<CertificateOptions> certOptions) : base(options, logger, encoder)
    {
        _certOptions = certOptions.Value;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            return Task.FromResult(AuthenticateResult.Fail("Missing Authorization header"));
        }

        var token = authHeader.ToString().Replace("Bearer ", "");

        try
        {
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                _certOptions.KeystorePath, _certOptions.KeystorePassword);

            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new X509SecurityKey(certificate),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(2)
            };

            var principal = handler.ValidateToken(token, validationParameters, out _);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Token validation failed");
            return Task.FromResult(AuthenticateResult.Fail("Invalid token"));
        }
    }
}
