using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using RestBA.Options;

namespace RestBA.HealthChecks;

public class CertificateHealthCheck : IHealthCheck
{
    private readonly CertificateOptions _options;

    public CertificateHealthCheck(IOptions<CertificateOptions> options)
    {
        _options = options.Value;
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_options.KeystorePath))
        {
            return Task.FromResult(
                HealthCheckResult.Unhealthy($"Certificate file not found at {_options.KeystorePath}"));
        }

        try
        {
            var cert = X509CertificateLoader.LoadPkcs12FromFile(
                _options.KeystorePath, _options.KeystorePassword);

            if (cert.NotAfter < DateTime.UtcNow)
            {
                return Task.FromResult(
                    HealthCheckResult.Unhealthy($"Certificate expired on {cert.NotAfter}"));
            }

            if (cert.NotAfter < DateTime.UtcNow.AddDays(30))
            {
                return Task.FromResult(
                    HealthCheckResult.Degraded($"Certificate expires on {cert.NotAfter}"));
            }

            return Task.FromResult(HealthCheckResult.Healthy("Certificate is valid"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                HealthCheckResult.Unhealthy("Failed to load certificate", ex));
        }
    }
}
