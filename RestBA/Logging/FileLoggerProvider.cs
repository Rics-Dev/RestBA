using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace RestBA.Logging;

public sealed class FileLoggerOptions
{
    public const string SectionName = "FileLogging";

    public string Directory { get; set; } = "logs";
    public string FilePrefix { get; set; } = "restba-";
    public int RetainedFileCount { get; set; } = 30;
}

[ProviderAlias("File")]
public sealed class FileLoggerProvider : ILoggerProvider, IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, FileLogger> _loggers = new(StringComparer.OrdinalIgnoreCase);
    private readonly BlockingCollection<string> _messageQueue = new(1024);
    private readonly FileLoggerOptions _options;
    private readonly Task _processTask;
    private readonly CancellationTokenSource _cts = new();

    public FileLoggerProvider(IOptions<FileLoggerOptions> options)
    {
        _options = options.Value;
        System.IO.Directory.CreateDirectory(_options.Directory);
        _processTask = Task.Run(ProcessLogQueue);
    }

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new FileLogger(name, _messageQueue));

    internal void EnqueueMessage(string message)
    {
        if (!_messageQueue.IsAddingCompleted)
        {
            try { _messageQueue.Add(message); }
            catch (InvalidOperationException) { }
        }
    }

    private async Task ProcessLogQueue()
    {
        try
        {
            foreach (var message in _messageQueue.GetConsumingEnumerable(_cts.Token))
            {
                var fileName = $"{_options.FilePrefix}{DateTime.Now:yyyyMMdd}.log";
                var filePath = Path.Combine(_options.Directory, fileName);

                await File.AppendAllTextAsync(filePath, message + Environment.NewLine);
            }
        }
        catch (OperationCanceledException) { }
    }

    private void CleanOldFiles()
    {
        try
        {
            var files = new DirectoryInfo(_options.Directory)
                .GetFiles($"{_options.FilePrefix}*.log")
                .OrderByDescending(f => f.CreationTime)
                .Skip(_options.RetainedFileCount);

            foreach (var file in files)
            {
                file.Delete();
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _messageQueue.CompleteAdding();
        try { _processTask.Wait(TimeSpan.FromSeconds(5)); }
        catch { }
        CleanOldFiles();
        _cts.Cancel();
        _cts.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        _messageQueue.CompleteAdding();
        try { await _processTask.WaitAsync(TimeSpan.FromSeconds(5)); }
        catch { }
        CleanOldFiles();
        await _cts.CancelAsync();
        _cts.Dispose();
    }
}

internal sealed class FileLogger(string categoryName, BlockingCollection<string> messageQueue) : ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;

        var message = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{logLevel,-12}] {categoryName}: {formatter(state, exception)}";
        if (exception is not null)
        {
            message += Environment.NewLine + exception;
        }

        if (!messageQueue.IsAddingCompleted)
        {
            try { messageQueue.Add(message); }
            catch (InvalidOperationException) { }
        }
    }
}

public static class FileLoggerExtensions
{
    public static ILoggingBuilder AddFile(this ILoggingBuilder builder, IConfiguration configuration)
    {
        builder.Services.Configure<FileLoggerOptions>(configuration.GetSection(FileLoggerOptions.SectionName));
        builder.Services.AddSingleton<ILoggerProvider, FileLoggerProvider>();
        return builder;
    }
}
