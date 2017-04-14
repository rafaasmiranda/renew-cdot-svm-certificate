#Requires -Version 3.0
<#
TODO: Help
#>


param (
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('SVM')]
    [string[]]$Vserver,
    [Parameter(Mandatory=$true)]
    [string]$EmailAddress,
    [ValidatePattern("\[a-z]{2}")]
    [string]$Country = ([System.Globalization.RegionInfo]((Get-Culture).Name)).TwoLetterISORegionName,
    [string]$ExpireDays = 365,
    [ValidateSet('sha1', 'sha256', 'md5')]
    [string]$HashFunction = "SHA256",
    [ValidateSet(512, 1024, 1536, 2048)]
    [int]$Size = 2048,
    [string]$State,
    [string]$Organization,
    [string]$OrganizationUnit,
    [string]$Locality
)

Begin {
    Write-Debug "Checking if the NetApp DataONTAP module is installed"

    if (!(Get-Module DataONTAP -ListAvailable)) {
        throw "NetApp DataONTAP PowerShell module was not found. Please install the module and run the script again."
    }
    else {
        Write-Debug "Importing DataONTAP module."
        Import-Module DataONTAP
    }

    Write-Debug "Checking if it is needed to connect to a cluster"
    
    if (!$Global:CurrentNcController) {
        try {
            Write-Verbose "Initiating cluster connection"
            $ClusterName = Read-Host -Prompt "Please inform the name or IP of the cluster"
            if (Test-Connection -ComputerName $ClusterName -Count 2 -Quiet) {
                Connect-NcController -Name $ClusterName -Credential (Get-Credential)
            }
            else {
                throw "Failure connecting to $ClusterName. Not Reachable."
            }
            
        }
        catch {
            throw "An error ocurred while attempting to connect to $ClusterName. $($Error[0].Exception.Message)"    
        }
    }
    else {
        Write-Verbose "Connected to Cluster $($Global:CurrentNcController.Name)"
    }
}

Process {
    # Date to compare with the certificate's date
    $ValidationDate = Get-Date
    foreach ($VserverItem in $Vserver) {
        # Get the certificate for the specified Vserver
        $certificate = Get-NcSecurityCertificate -Vserver $VserverItem
        # Check if the certificate is expired
        if ($certificate.ExpirationDateDT -gt $ValidationDate) {
            Write-Host "The certificate for $VserverItem is not expired. Nothing to do. :|"
        }
        else {
            # Building hashtable parameters for New-NcSecurityCertificate
            $NewCertParameters = @{
                CommonName = $VserverItem
                CertificateAuthority = $Global:CurrentNcController.Name
                Type = 'server'
                Vserver = $VserverItem
                Country = $Country
                ExpireDays = $ExpireDays
                HashFunction = $HashFunction
                State = $State
                Locality = $Locality
                Organization = $Organization
                OrganizationUnit = $OrganizationUnit
                EmailAddress = $EmailAddress
                Size = $Size
            }
        }
    }
}

End {

}