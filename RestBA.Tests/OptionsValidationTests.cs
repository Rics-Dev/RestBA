using System.ComponentModel.DataAnnotations;
using RestBA.Options;

namespace RestBA.Tests;

public class OptionsValidationTests
{
    [Fact]
    public void CertificateOptions_MissingKeystorePath_FailsValidation()
    {
        var options = new CertificateOptions
        {
            KeystorePath = "",
            IssuerName = "CN=test",
            SerialNumber = "00000000"
        };

        var results = new List<ValidationResult>();
        var isValid = Validator.TryValidateObject(options, new ValidationContext(options), results, true);

        Assert.False(isValid);
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(CertificateOptions.KeystorePath)));
    }

    [Fact]
    public void ExternalApiOptions_MissingRequiredFields_FailsValidation()
    {
        var options = new ExternalApiOptions();

        var results = new List<ValidationResult>();
        var isValid = Validator.TryValidateObject(options, new ValidationContext(options), results, true);

        Assert.False(isValid);
    }

    [Fact]
    public void DirectoryOptions_MissingPaths_FailsValidation()
    {
        var options = new DirectoryOptions();

        var results = new List<ValidationResult>();
        var isValid = Validator.TryValidateObject(options, new ValidationContext(options), results, true);

        Assert.False(isValid);
    }

    [Fact]
    public void PollingOptions_DefaultValues_AreValid()
    {
        var options = new PollingOptions();

        Assert.Equal(100, options.PollingIntervalMs);
        Assert.Equal(30000, options.FetchTimeoutMs);
        Assert.Equal(10, options.FetchSize);
    }

    [Fact]
    public void CertificateOptions_AllFieldsSet_PassesValidation()
    {
        var options = new CertificateOptions
        {
            KeystorePath = "certs/test.pfx",
            IssuerName = "CN=test",
            SerialNumber = "00000000"
        };

        var results = new List<ValidationResult>();
        var isValid = Validator.TryValidateObject(options, new ValidationContext(options), results, true);

        Assert.True(isValid);
        Assert.Empty(results);
    }
}
