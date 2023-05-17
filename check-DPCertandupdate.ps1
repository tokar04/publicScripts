<#
.SYNOPSIS
    This script will check expiration date of ConfigMgr DP certs and replaces if expiry date less than 15
    run this script from any server where ConfigMgr console is installed

.DESCRIPTION
    This script will check expiration date of ConfigMgr DP certs and replaces if expiry date less than 15
    run this script from any server where ConfigMgr console is installed

.PARAMETER DeploymentPointFQDN
FQDN of deploymentpoint to update

.PARAMETER CertificateTemplate
Certificate template name to use when requesting new certificate

.PARAMETER PFXpath
Path to save Exported PFX file

.PARAMETER PFXPassword
PFX file Password used for the new PFX. no need to save this PFX after update is complete

.EXAMPLE
    .\Check-DPCertAndUpdate.ps1 -DeploymentPointFQDN srv-cmdp01 -CertificateTemplate "ConfigMgr PXE servers" -PFXpath \\srv-cm01\sources$\DPcert -PFXPassword R@nd0mPa$$Word
    
.NOTES
    Script name: Check-DPCertAndUpdate.ps1
    Author:      torbjörn karlsson
    Contact:     @tokrandom
    DateCreated: 2020-05-26
    
    Version history:
    1.0 (2020-05-26) initial coding
    1.1 (2020-05-27) other way to check certificate in use before update
#>
param(
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Specify DeploymentPoint FQDN")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {
            # Check connection
            if ((Test-NetConnection -ComputerName $_ -InformationLevel Quiet) -eq $true) {
                return $true
            }
            else {
                throw "Unable to contact $_"
            }
        }
    )]
    [string]$DeploymentPointFQDN,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = "Specify CertificateTemplate certificate is issued with")]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateTemplate,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = "UNC folderpath to save PFX file")]
    [ValidatePattern("([A-Za-z0-9-]+)")]
    [ValidateScript({
        # Check if path contains any invalid characters
        if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw "$(Split-Path -Path $_ -Leaf) contains invallid characters"
        }
        else {
            # Check if the whole path exists
            if (Test-Path -Path $_ -PathType Container) {
                    return $true
            }
            else {
                throw "could not find $_ , check path to folder!"
            }
        }
    })]
    [string]$PFXpath,
    [Parameter(Position = 3, Mandatory = $true, HelpMessage = "Old PFX file password")]
    [ValidateNotNullOrEmpty()]
    [string]$PFXPassword
)
function Get-CertificateTemplate {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
 )
    Process {
        $temp = $Certificate.Extensions | where{$_.Oid.Value -eq "1.3.6.1.4.1.311.20.2"}
        if (!$temp) {
            $temp = $Certificate.Extensions | where{$_.Oid.Value -eq "1.3.6.1.4.1.311.21.7"}
        }
        $temp.Format(0)
    }
}

$orglocation=$PWD
Try {
    Write-Verbose "Attempting to import ConfigMgr Module" 
    Import-Module (Join-Path $(Split-Path $ENV:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1) -Verbose:$false 
    Write-Verbose "Successfully imported the ConfigMgr Module" 
} 
Catch {
         Throw "Failure to import ConfigMgr Cmdlets." 
}

#converting PFXPassword to securestring
$PFXPassword=$PFXPassword|ConvertTo-SecureString -AsPlainText -Force

#saving sitecode for later
$SiteCode=(Get-PSDrive -PSProvider CMSite).Name
Set-Location "$($SiteCode):"
$cmdpprop=(Get-CMDistributionPoint -SiteSystemServerName $DeploymentPointFQDN |select Properties).Properties
Set-Location $orglocation
#full path to save PFX file to
$filepath=$PFXpath +'\' +$($DeploymentPointFQDN)+(get-date -Format yyyyMMdd) + '.pfx'

if(((Get-PfxData -Password $mypwd -FilePath ($cmdpprop.Properties.props|where PropertyName -eq CertificateFile).Value1).EndEntityCertificates|select notafter -lt (get-date).adddays(15)){

    Invoke-Command -ComputerName $DeploymentPointFQDN -ScriptBlock {Get-ChildItem Cert:\LocalMachine\my | Where-Object{$_.Extensions | Where-Object{$_.oid.friendlyname -match "Template" -and $_.format(0) -match $using:CertificateTemplate}}| Export-PfxCertificate -FilePath $using:filepath -Password $using:mypwd}
    
    if (Test-Path -Path $filepath -PathType any) {
        Set-Location "$($SiteCode):"
        $DPname=Get-CMDistributionPoint -SiteSystemServerName $DeploymentPointFQDN
        Set-CMDistributionPoint -InputObject $DPname -CertificatePath $filepath -CertificatePassword $mypwd
        Set-Location $orglocation
    }
    else {
        throw "could not find $filepath,could not export PFX file"
    }
}
else {
    throw "no need to update certificate"
}
