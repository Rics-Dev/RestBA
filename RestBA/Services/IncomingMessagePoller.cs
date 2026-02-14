using Microsoft.Extensions.Options;
using RestBA.Models;
using RestBA.Options;

namespace RestBA.Services;

public class IncomingMessagePoller : BackgroundService
{
    private readonly ILogger<IncomingMessagePoller> _logger;
    private readonly DirectoryOptions _dirOptions;
    private readonly PollingOptions _pollingOptions;
    private readonly MXMessageService _messageService;
    private readonly SignatureService _signatureService;

    public IncomingMessagePoller(
        ILogger<IncomingMessagePoller> logger,
        IOptions<DirectoryOptions> dirOptions,
        IOptions<PollingOptions> pollingOptions,
        MXMessageService messageService,
        SignatureService signatureService)
    {
        _logger = logger;
        _dirOptions = dirOptions.Value;
        _pollingOptions = pollingOptions.Value;
        _messageService = messageService;
        _signatureService = signatureService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_dirOptions.IncomingFiles);

        _logger.LogInformation("Incoming message poller started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var messages = await _messageService.ReceiveMessages();

                foreach (var message in messages)
                {
                    await ProcessIncomingMessage(message);
                }

                await Task.Delay(_pollingOptions.PollingIntervalMs, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in message polling loop");
                await Task.Delay(5000, stoppingToken);
            }
        }
    }

    private async Task ProcessIncomingMessage(MXMessage message)
    {
        try
        {
            _logger.LogInformation("Processing incoming message: {TraceRef} - {Type}",
                message.TraceReference, message.Type);

            var isValid = _signatureService.VerifySignature(message.Document);

            if (!isValid)
            {
                _logger.LogWarning("Signature verification failed for message: {TraceRef}",
                    message.TraceReference);
            }

            var fileName = $"{message.Sender}_{message.Type}_{message.TraceReference}_{DateTime.Now:yyyyMMddHHmmss}.xml";
            var filePath = Path.Combine(_dirOptions.IncomingFiles, fileName);

            await File.WriteAllTextAsync(filePath, message.Document);

            _logger.LogInformation("Message saved to file: {FilePath}, Signature valid: {IsValid}",
                filePath, isValid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing incoming message: {TraceRef}",
                message.TraceReference);
        }
    }
}