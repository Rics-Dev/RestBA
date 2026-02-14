using System.ComponentModel.DataAnnotations;

namespace RestBA.Options;

public class CertificateOptions
{
    public const string SectionName = "Certificate";

    [Required]
    public string KeystorePath { get; set; } = string.Empty;
    public string? KeystorePassword { get; set; }
    [Required]
    public string IssuerName { get; set; } = string.Empty;
    [Required]
    public string SerialNumber { get; set; } = string.Empty;
}
