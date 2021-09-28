# TruenasCertificate
Installing and updating certificates on Truenas using PowerShell
Use these powershell scripts to install and later update Let's Encrypt certificates on a TrueNAS system from another device on your network. 

Before you get started, use Posh-ACME to download a certificate (or use any other valid certificate in base64 format). You'll also need to generate an API key on TrueNAS. API keys are available from the web interface by clicking **Settings > API Keys**


## First install
To install the first certificate, provide the servername, API key and paths to the certificate and private key files:
```powershell
$InstallOldArgs = @{
    TruenasServer  = "nas.anymoo.com" 
    ApiKey         = "yourapikey"
    ChainFilePath  = "C:\Powershell\oldcert\fullchain.cer" 
    KeyFilePath    = "C:\Powershell\oldcert\cert.key"
    CertnamePrefix = "LetsEncrypt" #Default value is "LE"
}
Install-TruenasCertificate @InstallOldArgs
```
The above command will connect to "nas.anymoo.com" and authenticate using the API key. It will then:
- Install the certificate
- Configure the main UI to use the certificate
- Configure WebDAV to use the certificate
- Configure FTP to use the certificate
- Finally the UI is reset to activate the new cert

If you don't want to use the certificate for all functions, you can exclude them with the switches `-NotForUi`, `-NotForWebdav` and `-NotForFTP`.


## Updates
The update command will check the provided certificate and compare it to installed certificates. It'll then replace that certiticate for any service that uses the same (and delete the old cert).

```powershell
$InstallNewArgs = @{
    TruenasServer = "nas.anymoo.com" 
    ApiKey   = "yourapikey"
    ChainFilePath = "c:\Powershell\newcert\fullchain.cer" 
    KeyFilePath   = "C:\Powershell\newcert\cert.key"
}
Update-TruenasCertificate @InstallNewArgs
```
The above command will connect to "nas.anymoo.com" and authenticate using the API key. It will then:
- Install the certificate
- Configure the main UI, WebDAV and FTP to use the new cert, if any of those used the old cert
- Delete the old cert
- Finally the UI is reset to activate the new cert

If there is not an old certificate installed, update will fall back and call the `Install-TruenasCertificate`.

## Reset
In case you want to reset back to the default "localhost" certificate, use the reset command
```powershell
$ResetArgs = @{
    TruenasServer = "nas.anymoo.com" 
    ApiKey   = "yourapikey"
}
Reset-TruenasCertificate
```
It'll set all services to use the default certificate. You'll have to manually remove any installed cert you want to get rid of.


