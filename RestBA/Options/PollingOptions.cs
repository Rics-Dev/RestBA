namespace RestBA.Options;

public class PollingOptions
{
    public const string SectionName = "Polling";

    public int PollingIntervalMs { get; set; } = 100;
    public int FetchTimeoutMs { get; set; } = 30000;
    public int FetchSize { get; set; } = 10;
}
