<#
TODO: Help
#>


param (
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('SVM')]
    [string[]]$Vserver,
    [bool]$ExpiredOnly = $true,
    [NetApp.Ontapi.Filer.C.NcController]$Controller
    
)

Begin {

}

Process {

}

End {
    
}