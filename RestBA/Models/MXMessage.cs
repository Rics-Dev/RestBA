namespace RestBA.Models;

public class MXMessage
{
    public string TraceReference { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Sender { get; set; } = string.Empty;
    public string Receiver { get; set; } = string.Empty;
    public string Document { get; set; } = string.Empty;
}
