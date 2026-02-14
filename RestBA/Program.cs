using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using RestBA.Authentication;
using RestBA.HealthChecks;
using RestBA.Options;
using RestBA.Services;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services));

    builder.Services.AddControllers();
    builder.Services.AddOpenApi();

    // Strongly-typed configuration
    builder.Services.AddOptions<CertificateOptions>()
        .Bind(builder.Configuration.GetSection(CertificateOptions.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    builder.Services.AddOptions<ExternalApiOptions>()
        .Bind(builder.Configuration.GetSection(ExternalApiOptions.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    builder.Services.AddOptions<DirectoryOptions>()
        .Bind(builder.Configuration.GetSection(DirectoryOptions.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    builder.Services.AddOptions<PollingOptions>()
        .Bind(builder.Configuration.GetSection(PollingOptions.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    // HTTP client with resilience
    builder.Services.AddHttpClient("ExternalApi")
        .AddStandardResilienceHandler();

    // Authentication
    builder.Services.AddAuthentication("ClientToken")
        .AddScheme<AuthenticationSchemeOptions, ClientTokenAuthHandler>("ClientToken", null);

    // Health checks
    builder.Services.AddHealthChecks()
        .AddCheck<CertificateHealthCheck>("certificate")
        .AddCheck<ExternalApiHealthCheck>("external_api");

    // Services
    builder.Services.AddSingleton<SignatureService>();
    builder.Services.AddSingleton<MXMessageService>();
    builder.Services.AddHostedService<OutgoingFileWatcher>();
    builder.Services.AddHostedService<IncomingMessagePoller>();

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.MapOpenApi();
    }

    app.UseExceptionHandler(exceptionApp =>
    {
        exceptionApp.Run(async context =>
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new { error = "An unexpected error occurred." });
        });
    });

    app.UseSerilogRequestLogging();
    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();
    app.MapHealthChecks("/health", new HealthCheckOptions
    {
        ResponseWriter = async (context, report) =>
        {
            context.Response.ContentType = "application/json";
            var result = new
            {
                status = report.Status.ToString(),
                checks = report.Entries.Select(e => new
                {
                    name = e.Key,
                    status = e.Value.Status.ToString(),
                    description = e.Value.Description
                }),
                duration = report.TotalDuration
            };
            await context.Response.WriteAsync(JsonSerializer.Serialize(result));
        }
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
