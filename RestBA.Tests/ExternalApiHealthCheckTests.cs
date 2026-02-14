using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using NSubstitute;
using RestBA.HealthChecks;
using RestBA.Options;

namespace RestBA.Tests;

public class ExternalApiHealthCheckTests
{
    [Fact]
    public async Task CheckHealthAsync_UnreachableApi_ReturnsUnhealthy()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new ExternalApiOptions
        {
            AuthUrl = "http://localhost:0/unreachable",
            BaseUrl = "http://localhost:0",
            Username = "test",
            Password = "test"
        });

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient());

        var healthCheck = new ExternalApiHealthCheck(httpClientFactory, options);

        var result = await healthCheck.CheckHealthAsync(
            new HealthCheckContext
            {
                Registration = new HealthCheckRegistration("external_api", healthCheck, null, null)
            });

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
    }
}
