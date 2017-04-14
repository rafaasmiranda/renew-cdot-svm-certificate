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
    } # End Module verification

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
    } # End cluster connection validation
} # End Begin Block

Process {
    # Date to compare with the certificate's date
    $ValidationDate = Get-Date
    foreach ($VserverItem in $Vserver) {
        # Get the certificate for the specified Vserver
        $CurrentCertificate = Get-NcSecurityCertificate -Vserver $VserverItem -Type "server"
        # Check if the certificate is expired
        if ($CurrentCertificate.ExpirationDateDT -gt $ValidationDate) {
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
            # End NewCertParameters

            if ($PSCmdlet.ShouldProcess($VserverItem,"Creating new certificate")) {
                try {
                    Write-Debug "Removing expired certificate $($CurrentCertificate.CommonName):$($CurrentCertificate.SerialNumber)"
                    Write-Verbose "Removing expired certificate on $VserverItem"

                    Remove-NcSecurityCertificate -Query $CurrentCertificate -ErrorAction Stop

                    Write-Debug "Creating a new self-signed ceritificate for $VserverItem"
                    Write-Verbose "Creating a new self-signed ceritificate for $VserverItem"

                    $NewCertificate = New-NcSecurityCertificate @NewCertParameters

                    Write-Debug "Enabling the new certificate for ssl authentication os vserver $VserverItem"
                    Write-Verbose "Enabling the new certificate for ssl authentication os vserver $VserverItem"

                    Set-NcSecuritySsl -Vserver $VserverItem -CertificateSerialNumber $NewCertificate.SerialNumber -CertificateAuthority $NewCertificate.CertificateAuthority -CommonName $NewCertificate.CommonName -EnableServerAuthentication $true -EnableClientAuthentication $true
                }
                catch {
                    Write-Error -Message "Error while creating new self-signed certificate for $VserverItem." -Exception $Error[0].Exception
                    continue
                } # End try-catch certificate creation
            } # End If ShouldContinue block
        } # End Else  Create New Certificate block
    } # End foreach vserver block
} # End Process block

End {

} # End End block