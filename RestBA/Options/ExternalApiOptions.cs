using System.ComponentModel.DataAnnotations;

namespace RestBA.Options;

public class ExternalApiOptions
{
    public const string SectionName = "ExternalAPI";

    [Required]
    public string AuthUrl { get; set; } = string.Empty;
    [Required]
    public string BaseUrl { get; set; } = string.Empty;
    public string ReceiverCode { get; set; } = string.Empty;
    [Required]
    public string Username { get; set; } = string.Empty;
    [Required]
    public string Password { get; set; } = string.Empty;
}
