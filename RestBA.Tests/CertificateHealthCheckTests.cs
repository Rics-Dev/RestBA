using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using RestBA.HealthChecks;
using RestBA.Options;

namespace RestBA.Tests;

public class CertificateHealthCheckTests
{
    [Fact]
    public async Task CheckHealthAsync_MissingFile_ReturnsUnhealthy()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new CertificateOptions
        {
            KeystorePath = "nonexistent.pfx",
            IssuerName = "CN=test",
            SerialNumber = "00000000"
        });

        var healthCheck = new CertificateHealthCheck(options);

        var result = await healthCheck.CheckHealthAsync(
            new HealthCheckContext
            {
                Registration = new HealthCheckRegistration("certificate", healthCheck, null, null)
            });

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("not found", result.Description);
    }
}
