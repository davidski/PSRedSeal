function Read-RSAccessResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal access query
    .OUTPUTS
        One custom object per traffic segment
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [XML]
        $RawXML
    )

    begin {
    }
    
    process {

        Write-Verbose "RawXml is $($rawXml.innerxml.tostring())"

        $table = @{}

        if ($rawXml.AccessResults.Message.innertext -like "*No access found*") {
            $table.add("Status", "No access found.")
            return [pscustomobject] $table
        } elseif ($null -ne $rawXml.AccessResults.Message) {
            throw "No response found: $($rawXml.innerxml.tostring())"
        }

        $rawXml.AccessResults.TrafficSegment | ForEach-Object {
                
            $table = @{}
            $table.add("Status", "TrafficSegment")
            $table.add("Source", $_.Source)
            $table.add("Destination", $_.Destination)
            $table.add("Traffic", $_.Traffic)

            [pscustomobject] $table
        }
    }
}
