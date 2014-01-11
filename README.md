# TERMS
Terms? We don't need no stinkin' terms. Don't be evil.

# Introduction
A PowerShell integration library for working with RedSeal.

## Sample Use Cases
+ Retrieve risk map data and store for trending and reporting
+ Develop rules for setting business values of assets
+ Extract vulnerability data
+ Maintain group memberships
+ Execute ad-hoc queries
+ Verify the status of your RedSeal server and report utilization stats

# News
11/21/2014 - Significant update to reflect 6.6 API changes. Apart from group modification 
support. Many big fixes throughout the code.

# Installation
There's More Than One Way To Do It (TMTOWTDI), but one of the simplest is via PsGet:

```PowerShell
(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex
Import-Module psget
Install-Module -URL https://github.com/davidski/RedSeal/archive/master.zip
```

# Command Set

Current cmdlets exposed include:
+ Connect-RSServer - Connect to a RedSeal server                                                                                               
+ ConvertFrom-RSDate - Utility function to convert RedSeal's data format into a .NET compatabile datetime object                                                                                             
+ Get-RSConnection - Retrieve current RedSeal connection status                                                                                               
+ Get-RSDevice - Retrieve a device                                                                                                   
+ Get-RSDeviceDetail - Fetch full details on a device                                                                                             
+ Get-RSGroup - Get policy group                                                                                                    
+ Get-RSHost - Get host object                                                                                                     
+ Get-RSHostDetail - Get details on host object                                                                                                
+ Get-RSReportList - Retrieve list of available RedSeal reports                                                                                               
+ Get-RSSubnet - Fetch subnet info                                                                                                   
+ Get-RSSystemStatus - Get the status of the RedSeal server                                                                                             
+ Get-RSView - Fetch all available views                                                                                                     
+ Invoke-RSDataQuery - Execute a RedSeal 6.6 DataQuery                                                                                             
+ Invoke-RSQuery - Invoke a RedSeal access/threat/detailed path query                                                                                                 
+ Read-RSAccessResult - Parse access query results                                                                                            
+ Read-RSImpactResult - Parse impact query results                                                                                            
+ Read-RSPathResult - Parse detailed path results                                                                                              
+ Read-RSReport - Retrieve and parse an Actuate report                                                                                                  
+ Read-RSThreatResult - Parse threat query results                                                                                            
+ Send-RSRequest - Send request to the proper version of RedSeal API                                                                                                 
+ Set-RSDataQuery - Prepare a data query                                                                                                
+ Set-RSGroup - Modify a group (RS 6.6+)                                                                                                    
+ Set-RSHost - Modify a host                                                                                                     
+ Set-RSHostValue - Modify a host's business value                                                                                                
+ Set-RSQueryTarget - Set a target or destination query object for subsequent query 

# Limitations
Only tested with PowerShell v3.
Support is targetted for v6.6 API. Support for v6.0 API is now deprecated and will be removed in future versions.

# Links
http://www.redsealnetworks.com
