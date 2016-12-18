[![Build Status](https://ci.appveyor.com/api/projects/status/github/davidski/PSRedSeal?svg=true)](https://ci.appveyor.com/project/davidski/PSRedSeal)

# Introduction
A PowerShell integration library for working with [RedSeal](https://www.redseal.net).

## Sample Use Cases
+ Retrieve risk map data and store for trending and reporting
+ Develop and implement rules governing asset business values
+ Extract vulnerability data
+ Maintain group memberships
+ Execute ad-hoc queries
+ Verify the status of your RedSeal server and report utilization stats

# Installation
There's More Than One Way To Do It (TMTOWTDI), but one of the simplest is via 
the [PowerShell Gallery](https://www.powershellgallery.com):

```PowerShell
Install-Module -Name PSRedSeal
```

Alternatively you can manually install the module by:

1. Downloading a zip build from the release page.
2. Unblocking and extracting the zip.
3. From PowerShell in the extracted directory enter: `{PowerShell} Install-Module -Path .\PSRedSeal`

# Command Set

Exposed cmdlets include (check `Get-Command -Module PSRedSeal` for latest):

+ Connect-RSServer - Connect to a RedSeal server
+ ConvertFrom-RSDate - Utility function to convert RedSeal's data format into a .NET compatible datetime object
+ Get-RSCollectionTasks - Retrieve the list of data collection tasks
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
+ Invoke-RSDataQuery - Execute a RedSeal DataQuery
+ Invoke-RSQuery - Invoke a RedSeal access/threat/detailed path query
+ Read-RSAccessResult - Parse access query results
+ Read-RSImpactResult - Parse impact query results
+ Read-RSPathResult - Parse detailed path results
+ Read-RSReport - Retrieve and parse an Actuate report
+ Read-RSThreatResult - Parse threat query results
+ Send-RSRequest - Send request to the proper version of RedSeal API
+ Set-RSDataQuery - Prepare a data query
+ Set-RSGroup - Modify a group
+ Set-RSHost - Modify a host
+ Set-RSHostValue - Modify a host's business value
+ Set-RSQueryTarget - Set a target or destination query object for subsequent query

# Limitations
- Only tested with PowerShell v3+
- RedSeal v7 API targeted.

# Links
[RedSeal](https://www.redseal.net/)
