<#
TODO: Help
#>


param (
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('SVM')]
    [string[]]$Vserver,
    [bool]$ExpiredOnly = $true
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

}

End {

}