# Script to install Jamf Pro Active Directory Certificate Services Connector
# ("ADCSC") and configure Microsoft IIS.

# To-Do:
# GUI for settings entry
# Document Parameters for each use case:
#  Setting up a stand-alone ADCSC
#  Setting up behind a reverse proxy or LB
#  Setting up an initial ADCSC and then a second (replica) for hot standby or load balanced.
#  Setting up a second (replica) for hot standby or load balanced.
# Parameterize the functions instead of using global vars.
# Fix the help section to match current reality.
# Screen shots of what iis iusr group, adcsc permissions, and iis settings should look like when done.
# On cleaninstall, remove existing certs and Windows Firewall entries
# parameter for cluster primary, cluster secondary so we know if we need to export the IIS TLS private key


# History:
#  v1   dev: 
#    Initial Release
#  v1.1 ol: 
#  Updated with new options
#    1) Supply a certificate for use in configuring HTTPS instead of generating a self-signed cert on the fly.
#    2) Add option to allow the Connector to authenticate to ADCS as a service account user instead of as a computer

param (
  [switch]$help                         = $false,
  [switch]$preCheckOnly                 = $false,
  [switch]$gui                          = $false,
  [switch]$replaceExistingPoolSite      = [switch]::Present,
  
  [string]$archivePath                  = "$PSScriptRoot\adcs.zip",
  [string]$installPath                  = "C:\inetpub\wwwroot\adcsconnector",
  [string]$siteBindHostName             = "",
  [int]$bindPort                        = 8443,

  [string]$appPoolName                  = "Jamf_ADCSC_Pool",
  [string]$siteName                     = "Jamf_ADCSC",

  [string]$certsFolder                  = "$PSScriptRoot\..\certs",

  [int]$selfSignedCertValidityYears     = 1,
  [int]$defaultPasswordLength           = 10,

  [switch]$Server_MakeSelfSignedCert    = [switch]::Present,
  [string]$Server_ExportIdentityFile    = $true,
  [switch]$Server_UseSuppliedIdent      = $false,
  [string]$Server_SuppliedIdentFileName = "server-cert.pfx",
  [string]$Server_SuppliedIdentFilePass = "LEAVEBLANK",
  [string[]]$Server_FQDNs               = @((Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain),

  [switch]$Client_MakeSelfSignedCert    = [switch]::Present,
  [string]$Client_JamfProHostName       = "myorg.jamfcloud.com",
  [switch]$Client_UseSuppliedCert       = $false,
  [string]$Client_SuppliedIdentFileName = "client-cert.cer",
  [string]$Client_SuppliedIdentFilePass = "LEAVEBLANK",

  # If you want the Connector to authenticate to ADCS with it's computer kerberos ticket, use this....
  [switch]$authToAdcsAsUser             = $true,
  [switch]$authToAdcsAsLocalUser        = $true,
  [switch]$authToAdcsAsDomainUser       = $false,
  [string]$authToAdcsAsDomainUserName   = '',
  [string]$authToAdcsAsDomainUserPass   = "",
  
# If you want the Connector to authenticate to ADCS with a domain user service account, use this...
#   [switch]$authToAdcsAsUser             = [switch]::Present,
#   [switch]$authToAdcsAsLocalUser        = $false,
#   [switch]$authToAdcsAsDomainUser       = [switch]::Present,
#   [string]$authToAdcsAsDomainUserName   = 'service-adcsc@myorg.org',
#   [string]$authToAdcsAsDomainUserPass   = "THIS SHOULD BE A PROMPT, NOT A PARAMETER SO YOU DON'T SAVE IT TO DISK",

  [switch]$Debug = $false
)

Function Show-Help(){
    $headingColor="Green"

    Write-Host "============================================================="
    Write-Host "Purpose: Setup the Jamf Pro AD Certificate Services Connector"
    Write-Host "Usage: .\deploy.ps1 [-param value]"
    Write-Host "Requires: Run as admin, presence of installer files"
    Write-Host "============================================================="
    Write-Host "Parameters:"
    # [switch]$help = $false
    Write-Host "-help" -ForegroundColor $headingColor
    Write-Host "  Display this message"
    # [switch]$preCheckOnly = $false
    Write-Host "-preCheckOnly" -ForegroundColor $headingColor
    Write-Host "  Check paramaters then quit without making any changes"
    # [string]$archivePath = "$PSScriptRoot\adcs.zip"
    Write-Host "-archivePath `"path to zip file`"" -ForegroundColor $headingColor
    Write-Host "  Path of the archive to deploy "
    Write-Host "  (Value: `"$archivePath`")"
    # [string]$installPath = "C:\inetpub\wwwroot\adcsconnector"
    Write-Host "-installPath `"value`"" -ForegroundColor $headingColor
    Write-Host "  Path to install site "
    Write-Host "  (Value: `"$installPath`")"
    # [string]$siteBindHostName = ""
    Write-Host "-siteBindHostName `"value`"" -ForegroundColor $headingColor
    Write-Host "  An optional/custom hostname for new site if not using the server's DNS name."
    Write-Host "  (Value: `"$siteBindHostName`")"
    # [int]$bindPort = 443
    Write-Host "-bindPort `"value`"" -ForegroundColor $headingColor
    Write-Host "  The TCP Port the IIS site should listen on."
    Write-Host "  (Value: `"$bindPort`")"
    # [switch]$skipAppPoolReset
    Write-Host "-replaceExistingPoolSite" -ForegroundColor $headingColor
    Write-Host "  Delete any pre-existing ADCS Connector App Pool and Site in IIS"
    Write-Host "  (Value: `"$replaceExistingPoolSite`")"
    # [string]$appPoolName = "AdcsConnectorPool"
    Write-Host "-appPoolName `"value`"" -ForegroundColor $headingColor
    Write-Host "  Name of the IIS Application Pool "
    Write-Host "  (Value: `"$appPoolName`")"
    # [string]$siteName = "AdcsConnector"
    Write-Host "-siteName `"value`"" -ForegroundColor $headingColor
    Write-Host "  Name of the IIS Site "
    Write-Host "  (Value: `"$siteName`")"
    # [switch]$Server_MakeSelfSignedCert = [switch]::Present
    Write-Host "-configHttpsSelfSigned" -ForegroundColor $headingColor
    Write-Host "  Configure HTTPS with self-signed certificate "
    Write-Host "  (Value: $configHttpsSelfSigned)"
    # [switch]$Server_UseSuppliedCert = $false
    Write-Host "-HTTPS_UseSuppliedCert" -ForegroundColor $headingColor
    Write-Host "  Configure HTTPS using a supplied .pfx file"
    Write-Host "  (Value: $Server_UseSuppliedCert)"
    # [string]$certsFolder="../certs"
    Write-Host "-certsFolder `"folderPath`"" -ForegroundColor $headingColor
    Write-Host "  Folder where generated certs should be saved"
    Write-Host "  (Value: `"$certsFolder`")"
    # [string]$suppliedCertFileName="connector-cert.pfx"
    Write-Host "-suppliedCertFileName `"username`"" -ForegroundColor $headingColor
    Write-Host "  Optional. If you want the Connector to authenticate to AD CS as a user"
    Write-Host "  instead of as a host, specify the user name. "
    Write-Host "  (Value: `"$suppliedCertFileName`")"
    # [string[]]$fqdns
    Write-Host "-fqdns `"value list`"" -ForegroundColor $headingColor
    Write-Host "  List of host names to use when creating a self-signed TLS certificate"
    Write-Host "  (Value: empty)"
    # [string]$Client_JamfProHostName
    Write-Host "-jamfProAuth_JamfProHostName `"hostname`"" -ForegroundColor $headingColor
    Write-Host "  Host name of Jamf Pro instance that will be communicating with this service. E.g. `"org.jamfcloud.com`""
    Write-Host "  (Value: `"$Client_JamfProHostName`")"
    # [string]$suppliedCertFileKeypass
    Write-Host "-suppliedCertFileKeypass `"password`"" -ForegroundColor $headingColor
    Write-Host "  The password to use if saving a Self-Signed TLS cert for use when "
    Write-Host "  installing other Connectors or to unlock a supplied .pfx file. Omit otherwise."
    Write-Host "  (Value: `"$suppliedCertFileKeypass`")"
    # [string]$authToAdcsAsUserName
    Write-Host "-authToAdcsAsUserName `"username`"" -ForegroundColor $headingColor
    Write-Host "  Optional. If you want the Connector to authenticate to AD CS as a user"
    Write-Host "  instead of as a host, specify the user name. The username will be the"
    Write-Host "  the one running the IIS thread."
    Write-Host "  (Value: `"$authToAdcsAsUserName`")"
    # [switch]$Debug = $false
    Write-Host "-debug" -ForegroundColor $headingColor
    Write-Host "  Optional. Include this flag for more verbose output"

    Write-Host ""
    exit
}

Function Write-LogDebug{
  Param([parameter(Position=0)]$MessageString)
  if ($debug) {
      #If string starts with [OK], color it green...
      if ($MessageString.StartsWith('[OK] ')) {
          Write-Host "[OK] " -NoNewline -ForegroundColor Green
          $MessageString = $MessageString.TrimStart("[OK] ")
      }
      #If string starts with [substep] or [info], indent it...
      if ($MessageString.StartsWith('[substep] ')) {
          Write-Host "[>substep] " -NoNewline 
          $MessageString = $MessageString.TrimStart("[substep] ")
      }
      if ($MessageString.StartsWith('[info] ')) {
          Write-Host "[>info] " -NoNewline 
          $MessageString = $MessageString.TrimStart("[info] ")
      }
      #Write the string
      Write-Host $MessageString -ForegroundColor Gray
  }       
}
Function Write-LogSection{
  Param([parameter(Position=0)]$MessageString)
  Write-Host "$(get-date -f yyyy'-'MM'-'dd' 'HH':'mm':'ss) $MessageString" -ForegroundColor Black -BackgroundColor Green
}
Function Write-LogError{
  Param([parameter(Position=0)]$MessageString)
  Write-Host "[error]" -NoNewline -BackgroundColor Red
  Write-Host " $MessageString I'm giving up."
  exit
}
Function Write-Log{
  Param([parameter(Position=0)]$MessageString)
  if ($MessageString.StartsWith('[notice] ')) {
    Write-Host ""
    # Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray,
    # Blue, Green, Cyan, Red, Magenta, Yellow, White
    Write-Host "$MessageString" -BackgroundColor Cyan -ForegroundColor Black
    Write-Host ""
  } else {
    Write-Host $MessageString
  }
}

Function Test-Environment() {
  Write-LogDebug "[step] Testing environment."
  Write-LogDebug "[>substep] Am I running on Windows or PowerShell Core?"
  if ($IsWindows){
    Write-LogDebug "[OK] Supported OS version found."
  } else {
    Write-Log "[warn] Not running on Windows... skipping environment check"
    return
  }
  Write-LogDebug "[>substep] Checking for minimum Windows version..."
  If([System.Version] (Get-WmiObject -class Win32_OperatingSystem).Version -lt [System.Version]"10.0.14393" -or -not (Get-WmiObject -class Win32_OperatingSystem).Name.Contains("Server")) {
    Write-LogError "The minimum Supported OS version is Windows Server 2016. "
  } else {
    Write-LogDebug "[OK] Supported OS version found."
  }

  Write-LogDebug "[>substep] Checking that we're running as admin..."
  #Require-s -RunAsAdministrator
  $user = [Security.Principal.WindowsIdentity]::GetCurrent();
  #(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if ( -Not (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) ) {
    Write-LogError("You'll need to run this script as Administrator.")
  } else {
    Write-LogDebug "[OK] Running as admin."
  }
}

Function Test-Parameters() {
  Write-LogDebug "[step] Testing parameters."

  # $skipWebAppInstall and $archivePath
  # If archive path is specified, check if it's a .zip file.
  if (Test-Path -Path $archivePath -PathType leaf -Include *.zip) {
    Write-LogDebug "[OK] A ZIP file exists at $archivePath"      
  } else {
    Write-LogError "ZIP archive not found at $archivePath. "
    exit
  }

  if ([string]::IsNullOrEmpty($appPoolName)){
    Write-LogError "appPoolName requires a value"
  }
  if ([string]::IsNullOrEmpty($siteName)){
    Write-LogError "siteName requires a value"
  }
  
  # If inastalling IIS, .\features.xml must be present.

  # If we're making a self-signed SSL cert, we'll need them to give us the passwords
  #  they want us to use when saving the keystores to disk.
  if($configHttpsSelfSigned) {
    if($httpsPass.Length -eq 0 -AND $clientPass.Length -eq 0) {
      Write-LogError "You need to provide values for httpsPass and clientPass"
    }
    if($httpsPass.Length -eq 0) {
      Write-LogError "You need to provide values for httpsPass"
    }
    if($clientPass.Length -eq 0) {
      Write-LogError "You need to provide values for clientPass"
    }
  }
  Write-LogDebug "[info] Parameter check completed."      
}

Function Install-IIS() {
  #Install IIS features
  Write-Log "[step] Enabling IIS and ASP.NET Windows features. This may take a minute..."
  try {
    $result = Install-WindowsFeature -ConfigurationFilePath "$PSScriptRoot\features.xml"
    $resultExitCode = $result.ExitCode
    Write-LogDebug "[debug] Install-WindowsFeature Status was `"$resultExitCode`""
  } catch {
    Write-LogError "Error enabling IIS and ASP.NET: $_"
  }
  Write-LogDebug "[OK] IIS and ASP.NET enabled."
}

Function Clear-IIS() {
  If (-Not $replaceExistingPoolSite) {
    Write-LogDebug "[step] Skipping removal of pre-exiting Connector site and app pool because -replaceExistingPoolSite was not specified."
    return
  }

  Write-LogDebug "[step] Removing any previously configured Connector appPool and site in IIS..."
  Write-LogDebug "[>substep] Checking if appPool `"${appPoolName}`" exists..."
  if (Test-Path "IIS:\AppPools\${appPoolName}") {
  #if ((Get-IISAppPool -Name "Jamf_ADCSC_Pool").Status) {
    Write-LogDebug "[info] AppPool already exists. Removing..."
    Remove-WebAppPool -Name "${appPoolName}"
    # Old way...
    # Remove-Item "IIS:\appPoolNames\${appPoolName}" -Recurse *>$null
    Write-LogDebug "[OK] `"$appPoolName`" Application Pool was removed"
  } else {
    Write-LogDebug "[OK] AppPool does not already exist."
  }
  # Test-Path "IIS:\AppPools\Jamf_ADCSC_Pool"
  # Test-Path "IIS:\appPoolNames\Jamf_ADCSC_Pool"     

  Write-LogDebug "[>substep] Checking if site `"${siteName}`" exists..."
  if (Test-Path "IIS:\Sites\$siteName") {
    try {
      Write-LogDebug "[info] Site exists. Removing..."
      Remove-Item "IIS:\Sites\$siteName" -Recurse *>$null
      Write-LogDebug "[OK] Site `"$siteName`" was removed"
    } catch {
      Write-LogError "Error removing site `"$siteName`"`: $_"
    }
  }else{
    Write-LogDebug "[OK] Site `"$siteName`" was not found so it does not need to be removed."
  }

  # Now that the old site has been deleted, make sure some other site isn't already using
  #  the requested listening port...
  if(Get-WebBinding -Port $bindPort) {
    Write-LogError "There's already another ISS site bound to port $bindPort. Remove it or select a different port for ADCSC."
  }

}

Function Install-ADCSC() {
  Write-Log "[step] Installing ADCS Connector IIS Site Files"
  Write-LogDebug "[substep] Create target directory"
  try {
    if(Test-Path $installPath) {
      Write-LogDebug "[info] Install path $installPath already exists. Deleting..."
      if($replaceExistingPoolSite) {
        Write-LogDebug "[replaceExistingPoolSite] Removing existing files from $installPath..."
        Remove-Item -Recurse -Force $installPath
        #Get-ChildItem $installPath -Recurse -Force | Remove-Item -Recurse -Force *>$null
        #Remove-Item $installPath -Recurse *>$null
        New-Item -Path $installPath -ItemType directory *>$null
      }
    } else {
      New-Item -Path $installPath -ItemType directory *>$null
      Write-LogDebug "[OK] Created folder `"$installPath`""    }
  }
  catch {
    Write-LogError "Could not create target directory: $_"
  }
  Write-LogDebug "[substep] Unzipping ADCSC site files to $installPath..."
  try {
    Expand-Archive -Path $archivePath -DestinationPath $installPath  *>$null
    Write-LogDebug "[OK] Un-zip Complete"
  }
  catch {
    Write-LogError "Could not extract archive to target directory: $_"
  }
}

Function Set-ADCSC-Site() {
  Write-Log "[step] Configuring ADCS Connector IIS Site and AppPool"
  Write-LogDebug "[substep] Creating $appPoolName Application Pool..."
  try {
    New-Item IIS:\AppPools\$appPoolName *>$null
    Write-LogDebug "[OK] Created App Pool"
  }
  catch {
    Write-LogError "Error creating application pool: $_"
  }
  Write-LogDebug "[substep] Setting AppPool managedRuntimeVersion Property"
  try {
    Set-ItemProperty IIS:\AppPools\$appPoolName managedRuntimeVersion v4.0 *>$null
    Write-LogDebug "[OK] Property set."
  }
  catch {
    Write-LogError "Error setting AppPool property: $_"
  }

  if ($authToAdcsAsUser) {
    Write-LogDebug "[substep] Setting AppPool to run as a specific user"
    try {
      Set-ItemProperty IIS:\AppPools\$appPoolName -name processModel -value @{userName="$authToAdcsAsDomainUserName";password="$authToAdcsAsDomainUserPass";identitytype="SpecificUser"} *>$null
      Write-LogDebug "[OK] Property set."
    }
    catch {
      Write-LogError "Error setting AppPool processModel property: $_"
    }
    $setting=Get-ItemProperty IIS:\AppPools\$appPoolName -name processModel
    Write-LogDebug "[info] The appPool's `"run-as`" properties are now set to : userName=$setting.userName, identityType=$setting.identityType"
  }
  Write-LogDebug "[substep] Creating IIS Site `"$siteName`""
  try {
    New-Item IIS:\Sites\$siteName -physicalPath $installPath -bindings @{protocol="https";bindingInformation="*:$bindPort`:$hostPath"} *>$null
    Set-ItemProperty IIS:\Sites\$siteName -name applicationPool -value $appPoolName *>$null
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$siteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert,SslRequireCert" *>$null
    Write-LogDebug "[OK] IIS Site created."
  }
  catch {
    Write-LogError "Error creating $siteName`: $_"
  }
}

Function Set-FirewallRule() {
  Write-Log "[step] Adding Windows Firewall rule to allow inbound TCP traffic on port $bindPort"
  try {
    New-NetFirewallRule -DisplayName "ADCS Connector" -Direction Inbound -LocalPort $bindPort -Protocol TCP -Action Allow *>$null
  }
  catch {
    Write-Host "Could not create firewall rule for port $bindPort`: $_"
  }
  Write-LogDebug "[OK] Added Windows firewall rule"
}

Function Set-HTTPS() {
  Write-Log "[step] Configuring IIS for HTTPS connections..."
  $binding = Get-WebBinding -Name "$siteName" -Protocol https

  if($Server_MakeSelfSignedCert) {
    Write-LogDebug "[substep] Generating a self-signed certificate for IIS HTTPS..."
    $CertCN=$Server_FQDNs[0]
    try {
      $cert = New-SelfSignedCertificate `
        -CertStoreLocation Cert:\LocalMachine\My `
        -Subject "CN=Jamf ADCS Connector" `
        -DnsName $Server_FQDNs `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature,CertSign,CRLSign,DataEncipherment,KeyEncipherment `
        -NotAfter (Get-Date).AddYears($selfSignedCertValidityYears)
        #todo -- I doubt all that key usage is needed. Test without it.
    } catch {
      Write-LogError "Could not generate and/or export a self-signed HTTPS certifiate for ${CertCN}`: $_"
    }
  } #  if($Server_MakeSelfSignedCert) {

  if($Server_UseSuppliedIdent){
    $Server_IdentPath="$certsFolder\$Server_SuppliedIdentFileName"
    # It's more convenient to accept the .pfx file password as a script parameter
    #  but it's not a safe practice outside of test environments.
    if ( $Server_SuppliedIdentFilePass = "" ) {
      $Server_SuppliedIdentFilePass_Secure = Read-Host -AsSecureString 'Please enter the password to use when reading the `"$Server_SuppliedIdentFileName`" server SSL certificate file'   
    }else{
      $Server_SuppliedIdentFilePass_Secure = ConvertTo-SecureString -String $Server_SuppliedIdentFilePass -AsPlainText -Force
    }
    $cert=Get-PfxCertificate -FilePath "C:\windows\system32\Test.pfx" -Password $Server_SuppliedIdentFilePass_Secure
  }

  Write-LogDebug "[substep] Attaching SSL identity to IIS site binding"
  $binding.AddSslCertificate($cert.GetCertHashString(), "my") *>$null
  
  Write-LogDebug "[substep] Exporting the public key for the IIS TLS identity -- we'll be importing it into Jamf Pro."
  $Server_CertPath="$certsFolder\server-cert.cer"
  Write-Log "[notice] The public key for the server SSL certificate has been saved to `"$Server_CertPath`". You'll need this file when entering your ADCS Connector info into Jamf Pro."
  if(Test-Path $Server_CertPath) {
    Remove-Item $Server_CertPath *>$null
  }
  Export-Certificate -Cert $cert -FilePath "$Server_CertPath" *>$null
  Write-LogDebug "[OK] Export the public key for import into Jamf Pro."

  Write-LogDebug "[substep] Making the public key a trusted root..."
  Import-Certificate -FilePath $Server_CertPath -CertStoreLocation Cert:\LocalMachine\Root *>$null

  if($Server_MakeSelfSignedCert) {
    # If we are load balancing we'll need to use this cert on other servers so
    #  if we just made it up on the fly, we'll export it so it can be copied over.
    $Server_IdentPath="$certsFolder\server-cert.pfx"
    if ($Server_ExportIdentityFile) {
      Write-Log "[substep] Exporting the server identity as .pfx for use on replica Connector server(s)."
      if(Test-Path $Server_IdentPath) {
        Remove-Item $Server_IdentPath *>$null
      }
      $KeystoreIdentPath="cert:\LocalMachine\My\$($cert.Thumbprint)"
      Write-LogDebug "[info] Windows keystore path : $KeystoreIdentPath"
      $Server_IdentityFilePass = New-PasswordString -CharSets "ULN"
      Write-Log "[notice] The server.pfx file will be saved to $KeystoreIdentPath. The keystore password is `"$Server_IdentityFilePass`". You'll need this only if you're going to be setting up additional Connector servers for load balancing or failover."
      $Server_IdentityFilePassSecure = ConvertTo-SecureString -String $Server_IdentityFilePass -Force –AsPlainText
      Export-PfxCertificate -Cert $KeystoreIdentPath -FilePath $Server_IdentPath -Password $Server_IdentityFilePassSecure >$null
    }
  }
  return $cert
}

Function Set-JamfProAuthCert() {
  Write-Log "[step] Generating or importing an identity for Jamf Pro authentication to IIS..."
  if($Client_MakeSelfSignedCert) {
    $Client_IdentSaveFilePath = "$certsFolder\client-cert.pfx"
    Write-LogDebug "[substep] Generating a self-signed certificate for $Client_JamfProHostName authentication to IIS..."
    $Server_CertCN=$Server_FQDNs[0]
    try {
      # Create a new cert signed by the SSL cert generated or imported above.
      # If we imported a cert it's purpose would need to include DigitalSignature
      $clientCert = New-SelfSignedCertificate `
        -CertStoreLocation Cert:\LocalMachine\My `
        -Subject "CN=Jamf Pro ADCSC Client Auth" `
        -DnsName $Client_JamfProHostName `
        -Signer $cert `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature,DataEncipherment,KeyEncipherment `
        -NotAfter (Get-Date).AddYears($selfSignedCertValidityYears)
      #Grab the b64 of the key -- we'll need it when setting it up as a client authentication cert in IIS...
      $clientB64 = [convert]::tobase64string($clientCert.RawData)
      if(Test-Path $Client_IdentSaveFilePath) {
        Remove-Item $Client_IdentSaveFilePath *>$null
      }
      Write-LogDebug "[substep] Exporting client certificate keystore..."   
      $Client_IdentKeystorePath="cert:\LocalMachine\My\$($clientCert.Thumbprint)"
      $Client_SelfSignedCertFilePass = New-PasswordString -CharSets "ULN"
      Write-Log "[notice] The client.pfx file will be saved to $Client_IdentSaveFilePath. The keystore password is `"$Client_SelfSignedCertFilePass`". You'll need this when configuring Jamf Pro to talk to this Connector."
      $Client_SelfSignedCertFilePass_Secure = ConvertTo-SecureString -String $Client_SelfSignedCertFilePass -Force –AsPlainText
      Export-PfxCertificate `
        -Cert $Client_IdentKeystorePath `
        -FilePath $Client_IdentSaveFilePath `
        -Password $Client_SelfSignedCertFilePass_Secure *>$null
      Write-LogDebug "[info] Client Authentication Certificate path in Windows keystore : $Client_IdentKeystorePath"
      Write-LogDebug "[OK] Client identity exported."
    } catch {
      Write-LogError "Could not generate ${Server_CertCN}-signed certificate for ${jamfProAuth_JamfProHostName}: $_"
    }
  }
  return $clientB64
}

Function Set-JamfProAuthUser() {
  # If you set $authenticateToAdcsAsUser to $false, ADCS Connector will use
  #  anonymous auth and authenticate to ADCS with the machine kerberos ticket and
  #  the machine record will have been given create manage certificates in ADCS.
  # If you don't get it set up correctly, you'll see a lot of requests piling up
  #  in certsrv's pending requests list. The "requested by" in the IIS request list
  #  will be "APPPOOL\AdcsConnectorPool". You'll see failed cert profiles in the 
  #   Jamf logs.
  # If you set it to $true it will configure IIS to use a user kerberos ticket
  #  and IIS will authenticate the user using the client certificate presented
  #  by Jamf Pro.
  # Typically when using user-auth, the user will have been created manually in AD 
  #  as a service account (cannot change password, passwor never expires) and the
  #  user will have been granted create/manage certificates in ADCS. The specified
  #  user will be added to the IIS_Users group on the Connector Server.

  if (! $authToAdcsAsUser) {
    Write-Log "[info] `$authToAdcsAsUser is false so I'm skipping user account creation and client Certificate Mapping configuration."
  } else {
    if ($authToAdcsAsLocalUser) {
      # We'll create a local user account and put it in iUsrs, but the CA admin will need to give it permissions to make certs.
      $authToAdcsAsUserName = $($siteName+"User")
      Write-Log "[step] Creating local user account `"$authToAdcsAsUserName`" for IIS Client Certificate Mapping Authentication."

      Write-LogDebug "[substep] Checking if the account already exists."
#        if(Get-WmiObject Win32_UserAccount -Filter "LocalAccount='true' and Name='$authToAdcsAsUserName'") {
#          Write-LogDebug "[info] User already exists. Deleting..."
#          Remove-LocalUser -Name "$authToAdcsAsUserName" # *>$null
#          Write-LogDebug "[OK] Old account deleted."
#        }else{
#          Write-LogDebug "[OK] User account does not already exist. "
#        }
      #Declare LocalUser Object
      $ObjLocalUser = $null
      Try {
        $ObjLocalUser = Get-LocalUser $authToAdcsAsUserName
      } 
      Catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
        Write-LogDebug "[OK] User $($authToAdcsAsUserName) was not found"
      }
      Catch {
        Write-LogError "An error occured while checking for local user account"
      }
      #Delete the user if it was found
      If ($ObjLocalUser) {
        Write-LogDebug "[info] User $($authToAdcsAsUserName) Already exists."
        Write-LogDebug "[>substep] Deleting old local user account"
        try {
          Remove-LocalUser -Name "$authToAdcsAsUserName" # *>$null
        } catch {
          Write-LogError "Could not remove pre-existing local account : $_"
        }
      }
      Write-LogDebug "[substep] Creating a password for the new local user account."
      try {
        $authToAdcsAsUserPass = New-PasswordString
        $authToAdcsAsUserPass_Secure=ConvertTo-SecureString $authToAdcsAsUserPass –asplaintext –force
      } catch {
        Write-LogError "Could not configure a password for the new local user : $_"
      }
      Write-LogDebug "[substep] Creating new local user account."
      try {
        # $localUser = New-LocalUser -Name "$authToAdcsAsUserName" -Password $authToAdcsAsUserPass_Secure -AccountNeverExpires -PasswordNeverExpires
        $newUser = New-LocalUser -Name "$authToAdcsAsUserName" -Password $authToAdcsAsUserPass_Secure -AccountNeverExpires -PasswordNeverExpires
        if (! $?) {
          Write-LogError "Could not create the new local user"      
        }
      } catch {
        Write-LogError "Could not create the new local user : $_"
      }

      Write-LogDebug "[>>substep] Adding new local account to IIS_IUSRS group."
      if ((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2 ) {
        Write-LogDebug "[info] This machine is a domain controller. I'll add the new user account to the domain's IIS_IUSRS group."
        Add-ADGroupMember -Identity "IIS_IUSRS" -Members "$authToAdcsAsUserName"
      } else {
        # Add-LocalGroupMember -Member "Jamf_ADCSCUser" -Group "IIS_IUSRS"
        Add-LocalGroupMember -Group "IIS_IUSRS" -Member "$authToAdcsAsUserName" *>$null
      }
      Write-LogDebug "[OK] Created new local user $authToAdcsAsUserName"
    }
    if ($authToAdcsAsDomainUser) {
      $authToAdcsAsUserName = $authToAdcsAsDomainUserName
      $authToAdcsAsUserPass = $authToAdcsAsDomainUserPass
    } 
    if($authToAdcsAsUserName.Contains('\')) {
      $domain=$authToAdcsAsUserName.Split('\')[0]
      Write-LogDebug "[info] domain=`"$domain`""
    } elseif ($authToAdcsAsUserName.Contains('@')) {
      $domain=$authToAdcsAsUserName.Split('@')[1]
      Write-LogDebug "[info] domain=`"$domain`""
    } else {
      $domain=''
    }
    if($Client_MakeSelfSignedCert) {
      Write-Log "[step] Configuring IIS Client Certificate Mapping Authentication for $authenticateToAdcsAsUserName..."
      Write-LogDebug "[substep] Setting default logon domain to $domain"
      try {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
          -location "$siteName" `
          -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" `
          -name "defaultLogonDomain" `
          -value $domain # *>$null
      }
      catch {
        Write-LogError "Could not set certificate mapping login domain: $_"
      }
      Write-LogDebug "[OK] Set certificate mapping login domain"


      Write-LogDebug "[substep] Enabling iisClientCertificateMappingAuthentication"
      try {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
          -location "$siteName" `
          -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" `
          -name "enabled" `
          -value "True" #*>$null
      }
      catch {
        Write-LogError "Could not enable iisClientCertificateMappingAuthentication: $_"
      }
      Write-LogDebug "[OK] iisClientCertificateMappingAuthentication enabled"

      Write-LogDebug "[substep] Disabling manyToOneCertificateMapping"
      try {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
          -location "$siteName" `
          -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" `
          -name "manyToOneCertificateMappingsEnabled" `
          -value "False" #*>$null
      }
      catch {
        Write-LogError "Could not disable manyToOneCertificateMapping: $_"
      }
      Write-LogDebug "[OK] manyToOneCertificateMapping disabled"

      Write-LogDebug "[substep] Setting property list for oneToOneMappings."
      Write-LogDebug "[info] userName=`"$authToAdcsAsUserName`""
      Write-LogDebug "[info] password=`"$authToAdcsAsUserPass`""
      Write-LogDebug "[info] certificate=`"$clientB64`""
      try {
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
          -location "$siteName" `
          -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/oneToOneMappings" `
          -name "." `
          -value @{userName="$authToAdcsAsUserName"; password="$authToAdcsAsUserPass"; certificate="$clientB64"} #*>$null
      } catch {
        Write-LogError "Could not configure IIS client certificate mapping authentication: $_"
      }
      Write-LogDebug "[OK] Client certificate configured for user authentication in IIS."

      # At the end of C:\Windows\System32\inetsrv\Config\applicationHost.config we would now expect to see something like...
      # <location path="AdcsConnector">
      #   <system.webServer>
      #       <security>
      #           <access sslFlags="Ssl, SslNegotiateCert, SslRequireCert" />
      #           <authentication>
      #               <iisClientCertificateMappingAuthentication enabled="true" manyToOneCertificateMappingsEnabled="false">
      #                   <oneToOneMappings>
      #                       <add userName="<accountName>" password="[enc:IISCngProvider:<longPasswordencryptedstring>f8FuiM0mrKZruF4QN4ueEj1e1N0=:enc]" certificate="" />
      #                   </oneToOneMappings>
      #               </iisClientCertificateMappingAuthentication>
      #           </authentication>
      #       </security>
      #   </system.webServer>
      # </location>

    }
  }
}

# Resource functions:

Function New-PasswordString([Int]$Size = $defaultPasswordLength, [Char[]]$CharSets = "ULNS", [Char[]]$Exclude) {
  # https://stackoverflow.com/a/37275209/821966
  $Chars = @();
  If (!$TokenSets) {
    $Global:TokenSets = @{
      U = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'                                #Upper case
      L = [Char[]]'abcdefghijklmnopqrstuvwxyz'                                #Lower case
      N = [Char[]]'0123456789'                                                #Numerals
      S = [Char[]]'!"#$%&''()*+,-./:;<=>?@[\]^_`{|}~'                         #Symbols
    }
  }
  $CharSets | ForEach-Object {
    $Tokens = $TokenSets."$_" | ForEach-Object {If ($Exclude -cNotContains $_) {$_}}
    If ($Tokens) {
      $TokensSet += $Tokens
      If ($_ -cle [Char]"Z") {$Chars += $Tokens | Get-Random}             #Character sets defined in upper case are mandatory
    }
  }
  While ($Chars.Count -lt $Size) {$Chars += $TokensSet | Get-Random}
  ($Chars | Sort-Object {Get-Random}) -Join ""                                #Mix the (mandatory) characters and output string
}

Function Save-Infofile {
  # Could use this to save pfx passwords to a file. Probably safer to just put them on screen, though.  
  Write-LogDebug "[step] Writing information file to certs folder"
  $text = "$(Get-Date)`n"
  $text = "${text}Protect this information and the certificates in this folder as you would your most secret password. "
  $text = "${text}The client key and password guard your certificate authority's certificate signing capabilities.`n"
  $text = "${text}[!] Delete this file and the certificates from this server as soon as you have securely transfered them to their required destingations. "
  $text = "${text}[!] Do not copy these files to or through any host whose security is uncertain.`n`n"
  $text = "${text}[notice] The server.pfx file was saved to $KeystoreIdentPath. The keystore password is `"$Server_IdentityFilePass`". You'll need this only if you're going to be setting up additional Connector servers for load balancing or failover.`n`n"
  $text = "${text}[notice] The public key for the server SSL certificate was saved to `"$Server_CertPath`". You'll need this file when configuring a ADCS Connector in Jamf Pro.`n`n"
  $text = "${text}[notice] The client.pfx file was saved to $Client_IdentSaveFilePath. The keystore password is `"$Client_SelfSignedCertFilePass`". You'll need this when configuring Jamf Pro to talk to this Connector."
  Set-Content -Path "${certsFolder}\CertificateInfo_" + $(get-date -f yyyy-MM-dd) + "_" + $(get-date -f HH-mm-ss) + ".txt" -Value $text
}

# Disreguard this GUI stuff... it's an unfinished PS GUI to build a setup wizard
# since the parameters are confusing.
Function Get-GUI () {
  if ($gui){
    if ($IsWindows){
      if ($args.Count -eq 0) {
        $buttonReturned = Get-InstallType
        "The $buttonReturned button was clicked."
      }
    }
  }
}
Function Get-InstallType () {
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.Application]::EnableVisualStyles()

  $Form                            = New-Object system.Windows.Forms.Form
  $Form.ClientSize                 = '509,242'
  $Form.text                       = "Jamf AD CS Connector Installer"
  $Form.TopMost                    = $false

  $Label1                          = New-Object system.Windows.Forms.Label
  $Label1.text                     = "What kind of Jamf AD Certificate Services Install are you performing?"
  $Label1.AutoSize                 = $true
  $Label1.width                    = 25
  $Label1.height                   = 10
  $Label1.location                 = New-Object System.Drawing.Point(14,26)
  $Label1.Font                     = 'Microsoft Sans Serif,10'

  $RadioButton1                    = New-Object system.Windows.Forms.RadioButton
  $RadioButton1.text               = "Single Instance"
  $RadioButton1.AutoSize           = $true
  $RadioButton1.width              = 104
  $RadioButton1.height             = 20
  $RadioButton1.location           = New-Object System.Drawing.Point(52,88)
  $RadioButton1.Font               = 'Microsoft Sans Serif,10'

  $RadioButton2                    = New-Object system.Windows.Forms.RadioButton
  $RadioButton2.text               = "Load Balanced (Multi-Instance)"
  $RadioButton2.AutoSize           = $true
  $RadioButton2.width              = 104
  $RadioButton2.height             = 20
  $RadioButton2.location           = New-Object System.Drawing.Point(52,121)
  $RadioButton2.Font               = 'Microsoft Sans Serif,10'

  $buttonOK                        = New-Object system.Windows.Forms.Button
  $buttonOK.text                   = "Continue"
  $buttonOK.width                  = 79
  $buttonOK.height                 = 30
  $buttonOK.location               = New-Object System.Drawing.Point(398,188)
  $buttonOK.Font                   = 'Microsoft Sans Serif,10'
  # $buttonOK.IsDefault              = $true
  $buttonOK.DialogResult           = OK
  #$buttonOK.Add_Click({$Form.Close()})

  $buttonCancel                    = New-Object system.Windows.Forms.Button
  $buttonCancel.text               = "Cancel"
  $buttonCancel.width              = 82
  $buttonCancel.height             = 30
  $buttonCancel.location           = New-Object System.Drawing.Point(292,188)
  $buttonCancel.Font               = 'Microsoft Sans Serif,10'
  $buttonOK.DialogResult           = Cancel

  #$buttonCancel.Add_Click({$Form.Close()})

  $Form.controls.AddRange(@($RadioButton1,$RadioButton2,$buttonOK,$buttonCancel,$Label1))
  #$Form.AcceptButton = $buttonOK
  #$Form.CancelButton = $buttonCancel
  $Form.ShowDialog()
}


## MAIN

Function Invoke-Main {
  If ($host.name -eq 'Windows Powershell ISE Host') {
    $debug=$true
    #$help=$true
    #$preCheckOnly=$true
  }
  If ($debug) {
    $VerbosePreference = 'Continue'
  }

  $thisScript=($MyInvocation.MyCommand.Name) # (split-path $MyInvocation.PSCommandPath -Leaf) works in functions, but not in IDE
  $IsWindows = ( [System.Environment]::OSVersion.Platform -eq "Win32NT" )
  Write-LogSection "[start] Running $thisScript"
  if($debug) { "[info] Running in debug mode, Running on Windows : $IsWindows" }
  # if($debug) { $PSBoundParameters }
  if($help) {Show-Help}
  Test-Environment
  if($preCheckOnly) {$debug=$true; Test-Parameters; Write-LogSection "[end] Finished test run"; exit} else {Test-Parameters}
  Get-GUI
  Install-IIS
  $VerbosePreference = 'SilentlyContinue'
  #-Cmdlet
  Import-Module WebAdministration
  $VerbosePreference = 'Continue'
  Clear-IIS
  Install-ADCSC
  Set-ADCSC-Site
  Set-FirewallRule
  $cert = Set-HTTPS
  $clientB64 = Set-JamfProAuthCert
  Set-JamfProAuthUser
  Write-LogSection "[end] Finished running $thisScript"

  # "You passed $($args.Count) arguments:"
}


$ErrorActionPreference = 'Stop'
Invoke-Main
