function Get-RSSubnet {
    <#
    .SYNOPSIS
        Get info on a given subnet
    .PARAMETER TreeID
        TreeID of subnet object
    .PARAMETER Name
        Name or IP address space of the subnet to get
    .PARAMETER XML
        Return the raw XML instead of a parsed object
    .PARAMETER Recurse
        Return objects for all alternatives, if multiple hits found
    .OUTPUTS
        One custom object per subnet.
#>

    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID = "4028aa8f2f63ce90012f63d85f6600de",
        
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false, ParameterSetName='SearchByName')]
        [Alias("IP")]
        [String]
        $Name,

        [Parameter(Mandatory=$false)]
        [Switch]
        $XML = $false,

        [Parameter(Mandatory=$false)]
        [Switch]
        $Recurse = $false
    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/subnet/$Name" 
        } else {
            $uri = "https://$script:server/data/subnet/id/$TreeID"
        }

        #$subnetXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $subnetXml = Send-RSRequest -uri $uri



        #if alternatives are returned then fetch all the alternatives and don't return a top level object
        if ($subnetXml.selectnodes("Message/Alternatives/Subnet").count -and $Recurse) {
               $subnetXml.selectnodes("Message/Alternatives/Subnet/ID").innertext | foreach {Get-RSSubnet -TreeID $_ -XML:$xml}
        } else {

            if ($XML) {
                $subnetXml
            } else {
                [pscustomobject] @{
                    TreeID = $subnetXml.Subnet.id
                    Name = $subnetXml.Subnet.name
                    Description = $subnetXml.Subnet.Description
                    DescriptionSource = $subnetXml.Subnet.DescriptionSource
                    TrustLevel = $subnetXml.subnet.TrustLevel
                    CIDR = $subnetXML.Subnet.CIDR
                    #HostTreeID = $subnetXml.subnet.hosts.host.treeid
                    #HostName = $subnetXml.subnet.hosts.host.name
                    Hosts      = $subnetXml.SelectNodes("/Subnet/Hosts/Host") |
                        ForEach-Object  { 
                            [pscustomobject]@{
                                Name = $_.Name
                                URL = $_.URL
                                TreeID = $_.TreeID
                            }
                        }
                }        
            }
        }
    }
}
