function Get-CertFileInfo(){
param(
    [Parameter(Mandatory=$true)]
    [string]$ChainFilePath
)
    $certChainBase64 = Get-Content $ChainFilePath 
    $select = $certChainBase64| Select-String -Pattern "CERTIFICATE" 
    $certBase64 = $certChainBase64 | Select-Object -Skip $select.LineNumber[0] -First ($select.LineNumber[1] - $select.LineNumber[0]-1)
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($certBase64))
}
function Reset-TruenasCertificate() {
    param(
    
        [Parameter(Mandatory = $true)]
        [string]$TruenasServer,
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [switch]$ForceHttpConnection
    )
    
    $RestMethodArgs = @{
        SkipCertificateCheck = $true 
        Headers = @{
            Authorization="Bearer $ApiKey"
            "Content-type" = "application/json"
        }
    }
    $ApiProtocol = if ($ForceHttpConnection) {"http"} else {"https"}
    $ApiUrl = "{0}://{1}/api/v2.0" -f $ApiProtocol, $TruenasServer

    Write-Debug "Getting installed certificates and selecting the first localhost cert"
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method Get 
    $NewCert = $RestResult | Where-Object {$_.common -eq "localhost"} | Sort-Object id | Select-Object -first 1 

    if ($Null -eq $NewCert) {throw("No default certificate found to reset to")}
    $SystemGeneralData = @{ ui_certificate     = $NewCert.id.ToString() } | ConvertTo-Json
    $webdavData        = @{ certssl            = $NewCert.id.ToString() } | ConvertTo-Json
    $ftpData           = @{ ssltls_certificate = $NewCert.id.ToString() } | ConvertTo-Json
    $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general" -Method Put -Body $SystemGeneralData 
    if ($result.ui_certificate.id -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for UI"}
    $result  = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/webdav" -Method Put -Body $webdavData        
    if ($result.certssl -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for Webdav"}
    $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/ftp" -Method Put -Body $ftpData           
    if ($result.ssltls_certificate -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for FTP"}
 
    Write-Debug "Restart the UI"
    $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general/ui_restart" -Method Get 
}
function Install-TruenasCertificate() {
param(

    [Parameter(Mandatory = $true)]
    [string]$TruenasServer,
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
    [Parameter(Mandatory = $true)]
    [string]$ChainFilePath,
    [Parameter(Mandatory = $true)]
    [string]$KeyFilePath,
    [switch]$ForceHttpConnection,
    [string]$CertnamePrefix="LE",
    [switch]$NotForUi,
    [switch]$NotForWebdav,
    [switch]$NotForFTP
)

    $RestMethodArgs = @{
        SkipCertificateCheck = $true 
        Headers = @{
            Authorization="Bearer $ApiKey"
            "Content-type" = "application/json"
        }
    }
    $ApiProtocol = if ($ForceHttpConnection) {"http"} else {"https"}
    $ApiUrl = "{0}://{1}/api/v2.0" -f $ApiProtocol, $TruenasServer
    Write-Debug "Validating certificate and getting info"
    try{
        $CertInfo = Get-CertFileInfo $ChainFilePath
        #Get the subject from the cert, replace * with ! if this is a wildcard
        $CertSubject = $certInfo.Subject.split("=")[1].replace("*","-").replace(".","_") 
        #Get the expiry date
        $CertExpire = $certInfo.NotAfter.ToString("yyyy-MM-dd")
        $TruenascertName = "{0}_{1}_{2}" -f $CertnamePrefix, $CertSubject, $CertExpire
    } catch {throw("Something went wrong reading the provided certificate: " + $_)}
    if (-not (Test-Path $KeyFilePath)){throw("The provided key file does not exist.")}

    write-debug "Testing connection to TrueNas"
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/state" -Method Get 
    if ($RestResult -ne "Ready") {throw("TrueNAS Not Ready")}

    Write-Debug "Getting installed certificates"
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method Get
    if (( $RestResult | Where-Object {$_.name -like $TruenascertName} | Measure-Object).Count -gt 0) {
        Throw("Cert is already installed")
    }

    $chainData = (get-Content $ChainFilePath) -join("`n")
    $keyData = (get-content $KeyFilePath) -join("`n")
    $CertCreateData = @{ 
        create_type = "CERTIFICATE_CREATE_IMPORTED"
        name = $TruenascertName
        certificate = $chainData
        privatekey = $keyData
    } | ConvertTo-Json
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method POST -Body $CertCreateData

    Write-Debug "Getting installed certificates"
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method Get
    $NewCert = $RestResult | Where-Object {$_.name -like $TruenascertName} | Select-Object -First 1




    $SystemGeneralData = @{ ui_certificate     = $NewCert.id.ToString() } | ConvertTo-Json
    $webdavData        = @{ certssl            = $NewCert.id.ToString() } | ConvertTo-Json
    $ftpData           = @{ ssltls_certificate = $NewCert.id.ToString() } | ConvertTo-Json
    if (-not $NotForUi ) {
        $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general" -Method Put -Body $SystemGeneralData 
        if ($result.ui_certificate.id -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for UI"}
    }
    if (-not $NotForWebDav) { 
        $result  = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/webdav" -Method Put -Body $webdavData        
        if ($result.certssl -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for Webdav"}
    }
    if (-not $NotForFTP   ) { 
        $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/ftp" -Method Put -Body $ftpData           
        if ($result.ssltls_certificate -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for FTP"}
    }
    Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general/ui_restart" -Method Get 
 
    Write-Debug "Restart the UI"
    $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general/ui_restart" -Method Get 
 
}

function Update-TruenasCertificate() {
    param(
    
        [Parameter(Mandatory = $true)]
        [string]$TruenasServer,
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [Parameter(Mandatory = $true)]
        [string]$ChainFilePath,
        [Parameter(Mandatory = $true)]
        [string]$KeyFilePath,
        [switch]$ForceHttpConnection,
        [string]$CertnamePrefix="LE"
    )
    
    $RestMethodArgs = @{
        SkipCertificateCheck = $true 
        Headers = @{
            Authorization="Bearer $ApiKey"
            "Content-type" = "application/json"
        }
    }
    $ApiProtocol = if ($ForceHttpConnection) {"http"} else {"https"}
    $ApiUrl = "{0}://{1}/api/v2.0" -f $ApiProtocol, $TruenasServer
    Write-Debug "Validating certificate and getting info"
    try{
        $CertInfo = Get-CertFileInfo $ChainFilePath
        #Get the subject from the cert, replace * with ! if this is a wildcard
        $CertSubject = $certInfo.Subject.split("=")[1].replace("*","-").replace(".","_") 
        #Get the expiry date
        $CertExpire = $certInfo.NotAfter.ToString("yyyy-MM-dd")
        $CertExpire = $certInfo.NotAfter.ToString("yyyy-MM-10")
        $TruenascertName = "{0}_{1}_{2}" -f $CertnamePrefix, $CertSubject, $CertExpire
    } catch {throw("Something went wrong reading the provided certificate: " + $_)}
    if (-not (Test-Path $KeyFilePath)){throw("The provided key file does not exist.")}
    
    write-debug "Testing connection to TrueNas"
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/state" -Method Get 
    if ($RestResult -ne "Ready") {throw("TrueNAS Not Ready: $RestResult")}
    
    Write-Debug "Getting installed certificates"
    $InstalledCerts = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method Get
    if (( $InstalledCerts | Where-Object {$_.name -like $TruenascertName} | Measure-Object).Count -gt 0) {
        Throw("Cert is already installed")
    }
    if (( $InstalledCerts | Where-Object {$_.common -eq $certInfo.Subject.split("=")[1]} | Measure-Object).Count -eq 0) {
        Write-Warning "Cert with same common name not yet installed. Calling Install-TruenasCertificate with default options"
        Install-TruenasCertificate -TruenasServer $TruenasServer -ApiKey $ApiKey -ChainFilePath $ChainFilePath -KeyFilePath $KeyFilePath 
    }
    Write-Debug "Select installed certificates to replace (that have the same subject)"
    $InstalledCertsToReplace = $InstalledCerts | Where-Object {$_.common -eq $certInfo.Subject.split("=")[1]}
    if (( $InstalledCertsToReplace | Where-Object {
            $_.common -eq $certInfo.Subject.split("=")[1] `
            -and [DateTime]::ParseExact($($_.until -replace("\s+"," ")), "ddd MMM d HH:mm:ss yyyy", $null) -ge $certInfo.NotAfter
        } | Measure-Object).Count -ge 1) {
        Throw("Cert with same common name and expiration already installed")
    }

    Write-Debug "Get current settings information for certificates in use"
    $SettingsUi = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general" -Method Get
    $SettingsWebdav  = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/webdav" -Method Get 
    $SettingsFtp     = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/ftp"    -Method Get    

    Write-Debug "Select the components to update the certificate for"
    if ($InstalledCertsToReplace.id -contains $SettingsUi.ui_certificate.id) { $ReplaceUi = $true }
    if ($InstalledCertsToReplace.id -contains $SettingsWebdav.certssl) { $ReplaceWebdav = $true }
    if ($InstalledCertsToReplace.id -contains $SettingsFtp.ssltls_certificate) { $ReplaceFtp = $true }
    
    Write-Debug "Install new certificate" 
    $chainData = (get-Content $ChainFilePath) -join("`n")
    $keyData = (get-content $KeyFilePath) -join("`n")
    $CertCreateData = @{ 
        create_type = "CERTIFICATE_CREATE_IMPORTED"
        name = $TruenascertName
        certificate = $chainData
        privatekey = $keyData
    } | ConvertTo-Json
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method POST -Body $CertCreateData

    Write-Debug "Getting installed certificates and select the newly installed cert"
    $RestResult = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate" -Method Get
    $NewCert = $RestResult | Where-Object {$_.name -like $TruenascertName} | Select-Object -First 1

    Write-Debug "Update the components that use the cert"
    $SystemGeneralData = @{ ui_certificate     = $NewCert.id.ToString() } | ConvertTo-Json
    $webdavData        = @{ certssl            = $NewCert.id.ToString() } | ConvertTo-Json
    $ftpData           = @{ ssltls_certificate = $NewCert.id.ToString() } | ConvertTo-Json
    if ($ReplaceUi) { 
        $Result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general" -Method Put -Body $SystemGeneralData 
        if ($result.ui_certificate.id -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for UI"}
    }
    if ($ReplaceWebdav) { 
        $result  = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/webdav" -Method Put -Body $webdavData        
        if ($result.certssl -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for Webdav"}
    }
    if ($ReplaceFtp) { 
        $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/ftp" -Method Put -Body $ftpData           
        if ($result.ssltls_certificate -notlike $NewCert.id) {Write-Warning "Something went wrong setting the certificate for FTP"}
    }
    Write-Debug "Delete the old, now unused certificates"
    foreach ($cid in $InstalledCertsToReplace.id) {
        $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/certificate/id/$cid" -Method Delete 
    }  

    Write-Debug "Restart the UI"
    $result = Invoke-RestMethod @RestMethodArgs -Uri "$ApiUrl/system/general/ui_restart" -Method Get 
}    


