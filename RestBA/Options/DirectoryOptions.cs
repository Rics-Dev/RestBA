using System.ComponentModel.DataAnnotations;

namespace RestBA.Options;

public class DirectoryOptions
{
    public const string SectionName = "Directories";

    [Required]
    public string OutgoingFiles { get; set; } = string.Empty;
    [Required]
    public string IncomingFiles { get; set; } = string.Empty;
    [Required]
    public string ProcessedFiles { get; set; } = string.Empty;
    [Required]
    public string ErrorFiles { get; set; } = string.Empty;
}
