<#
.SYNOPSIS
    Script to renew expired SSL self-signed certificates on NetApp Clustered DataONTAP Vservers
.DESCRIPTION
    The script takes a list of Vservers and creates new self-signed certificates for server authentication, therefore providing a quick way to clear the warnings generated in autosupport.
.PARAMETER Vserver
    List of Vservers which will have the certificates renewed
.PARAMETER EmailAddress
    E-mail address to be used in the certificate
.PARAMETER Country
    Two-letter country code to be used in the certificate. If it is not provided, the code will be acquired from the .Net Class System.Globalization.RegionInfo
.PARAMETER ExpireDays
    Number of days that will define the date of the certificate expiration. The minimum value is 30 days and the maximum is 3650
.PARAMETER HashFunction
    The type of function to be used in the certificate. The allowed values are sha1, sha256 and md5.
.PARAMETER Size
    Size of the requested certificate in bits. The default value is 2048. The allowed values are 512, 1024, 1536 and 2048.
.PARAMETER State
    The state where the vserver is located.
.PARAMETER Organization
    The name of the organization to be used on the certificate. Usually it is the company name.
.PARAMETER OrganizationUnit
    The name of the organization unit to be used on the certificate. Usually it is the name of the department that manages the equipment.
.PARAMETER Locality
    The general locality to be used in the certificate.
.PARAMETER DNSSuffix
    The dns suffix to be used in the certificate's common name.
.EXAMPLE
    To renew a certificate for a single Vserver
    New-CdotSVMSelfSignedCertificate.ps1 -Vserver vs01 -EmailAddress storage@example.com -Country US
.EXAMPLE
    To renew a certificate for a list of Vservers specifiyng 3650 days until the certificate expiration
    New-CdotSVMSelfSignedCertificate.ps1 -Vserver vs01, vs02 -EmailAddress storage@example.com -Country US -ExpirationDays 3650
.EXAMPLE
    To renew the certificates of all vservers in a Cluster, unless the type is system (it does not use a certificate).
    Get-NcVserver | ? {$PSItem.VserverType -ne "system"} | New-CdotSVMSelfSignedCertificate.ps1 -EmailAddress storage@example.com -Country US -Organization Contoso
    
    Notice that there is no need to specify the Vserver parameter, because the name of the vservers are being passed via pipeline.

.INPUTS
System.String[]

.OUTPUTS
None. The script does not (should not) generate output.
.COMPONENT
NetApp PowerShell Toolkit
.LINK
https://github.com/rafaasmiranda/renew-cdot-svm-certificate/blob/master/README.md
.LINK
GitHub Repository: https://github.com/rafaasmiranda/renew-cdot-svm-certificate
.LINK    
NetApp KB about certificates: https://kb.netapp.com/support/s/article/ka31A0000000wJ6QAI/how-to-renew-an-ssl-certificate-in-clustered-data-ontap?t=1492129898764
.LINK
Get-NcSecurityCertificate
.LINK
New-NcSecurityCertificate
.NOTES
    Author: Rafael Augusto Sena de Miranda
    GitHub: https://github.com/rafaasmiranda
    Twitter: @rafaasmiranda
#>

#Requires -Version 3.0
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('SVM')]
    [string[]]$Vserver,
    [Parameter(Mandatory=$true)]
    [string]$EmailAddress,
    [ValidatePattern("[A-Z]{2}")]
    [string]$Country = ([System.Globalization.RegionInfo]((Get-Culture).Name)).TwoLetterISORegionName,
    [ValidateRange(30, 3650)]
    [string]$ExpireDays = 365,
    [ValidateSet('sha1', 'sha256', 'md5')]
    [string]$HashFunction = "SHA256",
    [ValidateSet(512, 1024, 1536, 2048)]
    [int]$Size = 2048,
    [string]$State,
    [string]$Organization,
    [string]$OrganizationUnit,
    [string]$Locality,
    [ValidatePattern('^([\w\-\.]+)$')]
    [string]$DNSSuffix
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

    Write-Debug "Checking if there is a connection to a Cluster"
    
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

    #TODO: Função para renovar o certificado.

} # End Begin Block

Process {
    # Date to compare with the certificate's date
    $ValidationDate = Get-Date
    foreach ($VserverItem in $Vserver) {
        # Get vserver data
        $VserverInfo = Get-NcVserver -Name $VserverItem
        if (!$VserverInfo) {
            Write-Error -Message "The vserver $VserverItem was not found." -Category ObjectNotFound -TargetObject $VserverItem -RecommendedAction "Ensure the vserver name is correct and try again"
            continue
        } elseif ($VserverInfo.VserverType -notmatch '(admin|data|node)') {
            Write-Warning "Certificate creation is not needed for vserver $($VserverInfo.Vserver): type is $($VserverInfo.VserverType)"
            continue
        }
        
        # Get the current SSL certificate in use for the vserver
        $VserverSSLInfo = Get-NcSecuritySsl -Vserver $VserverInfo.Vserver
        $VserverCurrentSSLCertificate = Get-NcSecurityCertificate -SerialNumber $VserverSSLInfo.CertificateSerialNumber

        # Check if the certificate is expired
        Write-Debug "$($VserverCurrentSSLCertificate.CommonName). ExpirationDate: $($VserverCurrentSSLCertificate.ExpirationDate). ExpirationDateDT: $($VserverCurrentSSLCertificate.ExpirationDateDT)"
        if ($VserverCurrentSSLCertificate.ExpirationDateDT -gt $ValidationDate) {
            Write-Host "The certificate for $VserverItem is not expired. Nothing to do. :)" -ForegroundColor Green
        } else {
            # Building hashtable parameters for New-NcSecurityCertificate
            $NewCertParameters = @{
                CommonName           = if($DNSSuffix) {$VserverInfo.Vserver + "." + $DNSSuffix} else {$VserverInfo.Vserver}
                CertificateAuthority = $Global:CurrentNcController.Name
                Type                 = 'server'
                Vserver              = $VserverInfo.Vserver
                Country              = $Country.ToUpper()
                ExpireDays           = $ExpireDays
                HashFunction         = $HashFunction
                State                = $State
                Locality             = $Locality
                Organization         = $Organization
                OrganizationUnit     = $OrganizationUnit
                EmailAddress         = $EmailAddress
                Size                 = $Size
            }
            # End NewCertParameters

            if ($PSCmdlet.ShouldProcess($VserverItem, "Creating new certificate")) {
                try {
                    Write-Debug "Removing expired certificate $($VserverCurrentSSLCertificate.CommonName):$($VserverCurrentSSLCertificate.SerialNumber)"
                    Write-Verbose "Removing expired certificate on $VserverItem"

                    Remove-NcSecurityCertificate -CommonName $VserverCurrentSSLCertificate.CommonName -Type $VserverCurrentSSLCertificate.Type -SerialNumber $VserverCurrentSSLCertificate.SerialNumber -Vserver $VserverCurrentSSLCertificate.Vserver

                    Write-Debug "Creating a new self-signed ceritificate for $VserverItem"
                    Write-Verbose "Creating a new self-signed ceritificate for $VserverItem"

                    $NewCertificate = New-NcSecurityCertificate @NewCertParameters

                    Write-Debug "Enabling the new certificate for ssl authentication os vserver $VserverItem"
                    Write-Verbose "Enabling the new certificate for ssl authentication os vserver $VserverItem"

                    Set-NcSecuritySsl -Vserver $VserverItem -CertificateSerialNumber $NewCertificate.SerialNumber -CertificateAuthority $NewCertificate.CertificateAuthority -CommonName $NewCertificate.CommonName -EnableServerAuthentication $true -EnableClientAuthentication $false
                } catch {
                    Write-Error -Message "Error while creating new self-signed certificate for $VserverItem." -Exception $Error[0].Exception
                    continue
                } # End try-catch certificate creation
            } # End If ShouldContinue block
        } # End Else  Create New Certificate block
    } # End foreach vserver block
} # End Process block

End {

} # End End block