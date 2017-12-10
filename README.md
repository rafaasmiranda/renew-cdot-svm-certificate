# renew-cdot-svm-certificate
Script to renew the self signed certificates on NetApp Clustered Data ONTAP SVMs

## Requirements

1.  PowerShell 3.0 or greater
2.  NetApp PowerShell Toolkit

## Instructions
The script takes a list of vservers and creates a new self-signed certificate if the one in use is expired.  
If there's no connection to a cDOT cluster, the script will prompt for a cluster name, a credential and attempt to establish the connection.
``` powershell
PS C:\> .\New-CdotSVMSelfSignedCertificate.ps1 -Vserver vs01, vs02 -Country "US" -EmailAddress "storage@example.com" 
```
