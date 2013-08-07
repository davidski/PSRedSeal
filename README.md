# TERMS
Terms? We don't need no stinkin' terms. Don't be evil.

# Introduction
A PowerShell integration library for working with RedSeal.

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
Support is complete for RedSeal v6.0 API. Partial support for v6.6 API.

# To Dos
[x] Rewrite away from the use of Invoke-RESTMethod to WebMethod calls. RestMethod is just too buggy (timeout issues, URL mangling, etc.).
[ ] Completely implement RS 6.6 API
[x] Fall back mode to RS 6.0 API
[ ] Support group modification
[ ] Support DataQueries
[ ] Better verification of credentials upon connection setup
[ ] Support impact and detailed path queries
[ ] Modify the subnet queries to return host and device objects instead of unwound treeID/hostname, treeid/devicename lists


# Links
http://www.redsealnetworks.com