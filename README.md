# RestBA Configuration Secrets

This app reads the keystore password and external API credentials from configuration. For local development, use User Secrets. For any environment, you can also use environment variables.

## User Secrets (local dev)

In Visual Studio, right-click the `RestBA` project and select **Manage User Secrets**, then add:

```json
{
  "Certificate": {
    "KeystorePassword": "change-me"
  },
  "ExternalAPI": {
    "Username": "change-me",
    "Password": "change-me"
  }
}
```

CLI alternative (from the `RestBA` project directory):

```powershell
dotnet user-secrets set "Certificate:KeystorePassword" "change-me"
dotnet user-secrets set "ExternalAPI:Username" "change-me"
dotnet user-secrets set "ExternalAPI:Password" "change-me"


dotnet user-secrets list


To remove a specific key:
dotnet user-secrets remove "Certificate:KeystorePassword"
To wipe all secrets for the project:

dotnet user-secrets clear
```



## Environment Variables (any environment)

Use double underscores to represent nested sections:

```powershell
setx Certificate__KeystorePassword "change-me"
setx ExternalAPI__Username "change-me"
setx ExternalAPI__Password "change-me"
```

These values override `appsettings.json` automatically.

---

## Deployment to a Windows 10 Machine

### Option 1: Self-Contained Deployment (no .NET runtime needed on the target)

Publish the app with all dependencies included:

```powershell
dotnet publish -c Release -r win-x64 --self-contained -o ./publish
```

On the **target machine**:

1. Copy the entire `publish` folder (e.g., to `C:\RestBA`).
2. Ensure the required files and directories exist relative to the app:
   - `certs/certificate.pfx`
   - `data/outgoing`, `data/incoming`, `data/processed`, `data/errors`
3. Update `appsettings.json` with the correct values for `Certificate`, `ExternalAPI`, etc., or set environment variables (see above).
4. Run the app:

```powershell
.\RestBA.exe --urls "https://0.0.0.0:5001"
```

### Option 2: Framework-Dependent Deployment (smaller output, requires .NET 10 runtime)

```powershell
dotnet publish -c Release -o ./publish
```

On the target machine, install the [.NET 10 ASP.NET Core Runtime](https://dotnet.microsoft.com/download/dotnet/10.0), then run:

```powershell
dotnet RestBA.dll --urls "https://0.0.0.0:5001"
```

### Run as a Windows Service

To keep the app running after logoff and auto-start on boot:

1. Add the Windows Service hosting package:

```powershell
dotnet add package Microsoft.Extensions.Hosting.WindowsServices
```

2. Add `builder.Host.UseWindowsService();` in `Program.cs` right after `WebApplication.CreateBuilder(args)`.

3. Publish (self-contained):

```powershell
dotnet publish -c Release -r win-x64 --self-contained -o C:\RestBA
```

4. Register and start the service on the target machine (**run as Administrator**):

```powershell
sc.exe create RestBA binPath="C:\RestBA\RestBA.exe --urls https://0.0.0.0:5001" start=auto
sc.exe start RestBA
```

To stop and remove the service:

```powershell
sc.exe stop RestBA
sc.exe delete RestBA
```

### Deployment Checklist

| Item | Action |
|---|---|
| **Certificate** | Copy `certs/certificate.pfx` to the same relative path |
| **Directories** | Create `data/outgoing`, `data/incoming`, `data/processed`, `data/errors` |
| **appsettings.json** | Update `ExternalAPI` credentials, `Certificate.KeystorePassword`, etc. |
| **Firewall** | Open the listening port (e.g., 5001) in Windows Firewall |
| **Secrets** | Avoid storing passwords in `appsettings.json` — use environment variables instead |
