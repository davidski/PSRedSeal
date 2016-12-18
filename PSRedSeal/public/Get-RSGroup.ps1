function Get-RSGroup {
    <#
    .SYNOPSIS
        Get one or more groups from RedSeal
    .PARAMETER GroupPath
        Full path to the group
    .PARAMETER Recurse
        Crawl through subgroups and return individual group objects
    .PARAMETER XML
        Boolean switch to return the raw XML instead of a parsed object
    .OUTPUTS
        One custom object per group.
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [String]
        $GroupPath = "/Server+Core+Zoning+Standards/Clients",
   
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]
        $XML = $false
    )
    
    begin {
    }

    process {

        $uri = "https://" + $script:Server + "/data/group" + $groupPath
        
        Write-Debug "Query URI is $uri"

        #$groupXml = Invoke-RestMethod -Uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $groupXml = Send-RSRequest -uri $uri

        Write-Debug "Response is $($groupXml.InnerXML.tostring())"

        #test for no group found (bad URI)
        if ($groupXml.message.text -like 'No group found*') {
            return $groupXML.message.text
        }
        
        #test for generic failure (test for NPE)
        if ($groupXml.message.text -like 'Get Failed*') {
            return $null
        }

        $groupXml = $groupXml.FullGroup

        if ($XML) {
            $groupXml
        } else {
            [pscustomobject] @{
                GroupName    = $groupXml.Name
                GroupPath    = $groupXml.path
                Comments     = $groupXml.comments
                SubGroupName = $groupXml.SelectNodes("/FullGroup/Groups/Group/Name")."#text"
                SubGroupPath = $groupXml.SelectNodes("/FullGroup/Groups/Group/Path")."#text"
                SubGroups    = $groupXml.SelectNodes("/FullGroup/Groups/Group") |
                    ForEach-Object  { 
                        [pscustomobject]@{
                            Name = $_.Name
                            URL = $_.URL
                            Path = $_.Path
                        }
                    } 
                SubnetID     = $groupXml.SelectNodes("/FullGroup/Subnets/Subnet/ID")."#text"
                Subnets      = @($groupXml.SelectNodes("/FullGroup/Subnets/Subnet") |
                    ForEach-Object  { 
                        [pscustomobject]@{
                            Name = $_.Name
                            URL = $_.URL
                            CIDR = $_.CIDR
                            ID = $_.ID
                            TrustLevel = $_.TrustLevel
                            Description = $_.Description
                        }
                })
                HostTreeID   = $groupXml.SelectNodes("/FullGroup/Computers/Host/TreeId")."#text"
                HostName     = $groupXml.SelectNodes("/FullGroup/Computers/Host/Name")."#text"
                Hosts        = @($groupXml.SelectNodes("/FullGroup/Computers/Host") | 
                    ForEach-Object  { 
                        [pscustomobject]@{
                            Name = $_.Name
                            URL = $_.URL
                            TreeID = $_.TreeID
                        }
                })
                Devices      = @($groupXml.SelectNodes("/FullGroup/Computers/Device") |
                    ForEach-Object  { 
                        [pscustomobject]@{
                        Name = $_.Name
                        URL = $_.URL
                        TreeID = $_.TreeID
                        PrimaryCapability = $_.PrimaryCapability
                    }
                })
            }
        }

        #if we have subgroups, test if recursion is requested
        if ($recurse -and ($groupXml.groups.group.path).count -ge 1) {
            $groupXml.groups.group.path | Get-RSGroup -Recurse -XML:$XML
        }
    }
}
