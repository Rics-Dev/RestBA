using System.Threading.Channels;
using System.Xml;
using Microsoft.Extensions.Options;
using RestBA.Options;

namespace RestBA.Services;

public class OutgoingFileWatcher : BackgroundService
{
    private readonly ILogger<OutgoingFileWatcher> _logger;
    private readonly DirectoryOptions _dirOptions;
    private readonly SignatureService _signatureService;
    private readonly MXMessageService _messageService;
    private readonly Channel<string> _fileChannel = Channel.CreateUnbounded<string>();
    private FileSystemWatcher? _watcher;

    public OutgoingFileWatcher(
        ILogger<OutgoingFileWatcher> logger,
        IOptions<DirectoryOptions> dirOptions,
        SignatureService signatureService,
        MXMessageService messageService)
    {
        _logger = logger;
        _dirOptions = dirOptions.Value;
        _signatureService = signatureService;
        _messageService = messageService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_dirOptions.OutgoingFiles);

        _watcher = new FileSystemWatcher(_dirOptions.OutgoingFiles)
        {
            Filter = "*.xml",
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };

        _watcher.Created += (sender, e) => _fileChannel.Writer.TryWrite(e.FullPath);

        _logger.LogInformation("Outgoing file watcher started on: {Path}", _dirOptions.OutgoingFiles);

        await foreach (var filePath in _fileChannel.Reader.ReadAllAsync(stoppingToken))
        {
            await ProcessFile(filePath, stoppingToken);
        }
    }

    private async Task ProcessFile(string filePath, CancellationToken stoppingToken)
    {
        try
        {
            var content = await ReadFileWithRetryAsync(filePath, stoppingToken);

            _logger.LogInformation("Processing file: {FilePath}", filePath);

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(content);

            var nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
            nsManager.AddNamespace("cma", "urn:cma:stp:xsd:stp.1.0");
            nsManager.AddNamespace("head", "urn:iso:std:iso:20022:tech:xsd:head.001.001.01");

            var bizMsgIdrNode = xmlDoc.SelectSingleNode("//head:BizMsgIdr", nsManager);
            var traceReference = bizMsgIdrNode?.InnerText ?? Guid.NewGuid().ToString();

            var msgDefIdrNode = xmlDoc.SelectSingleNode("//head:MsgDefIdr", nsManager);
            var messageType = msgDefIdrNode?.InnerText ?? "unknown";

            var signedContent = _signatureService.SignMXDocument(content);
            var success = await _messageService.SendMessage(traceReference, messageType, signedContent);

            if (success)
            {
                var processedPath = Path.Combine(
                    _dirOptions.ProcessedFiles,
                    $"{Path.GetFileNameWithoutExtension(filePath)}_{DateTime.Now:yyyyMMddHHmmss}.xml"
                );
                Directory.CreateDirectory(_dirOptions.ProcessedFiles);
                File.Move(filePath, processedPath, true);

                _logger.LogInformation("File processed and moved: {ProcessedPath}", processedPath);
            }
            else
            {
                MoveToErrorDirectory(filePath, "ERROR");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing file: {FilePath}", filePath);
            MoveToErrorDirectory(filePath, "EXCEPTION");
        }
    }

    private async Task<string> ReadFileWithRetryAsync(
        string filePath, CancellationToken cancellationToken, int maxRetries = 5)
    {
        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                return await File.ReadAllTextAsync(filePath, cancellationToken);
            }
            catch (IOException) when (attempt < maxRetries - 1)
            {
                var delay = TimeSpan.FromMilliseconds(100 * Math.Pow(2, attempt));
                _logger.LogDebug(
                    "File {FilePath} is locked, retrying in {Delay}ms (attempt {Attempt}/{Max})",
                    filePath, delay.TotalMilliseconds, attempt + 1, maxRetries);
                await Task.Delay(delay, cancellationToken);
            }
        }

        throw new IOException($"Unable to read file {filePath} after {maxRetries} attempts");
    }

    private void MoveToErrorDirectory(string filePath, string suffix)
    {
        try
        {
            var errorPath = Path.Combine(
                _dirOptions.ErrorFiles,
                $"{Path.GetFileNameWithoutExtension(filePath)}_{DateTime.Now:yyyyMMddHHmmss}_{suffix}.xml"
            );
            Directory.CreateDirectory(_dirOptions.ErrorFiles);
            File.Move(filePath, errorPath, true);

            _logger.LogError("File moved to errors: {ErrorPath}", errorPath);
        }
        catch (Exception moveEx)
        {
            _logger.LogError(moveEx, "Failed to move error file");
        }
    }

    public override void Dispose()
    {
        _watcher?.Dispose();
        base.Dispose();
    }
}