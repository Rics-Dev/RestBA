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
