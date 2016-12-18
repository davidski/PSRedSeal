function Read-RSPathResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal detailed path query
    .PARAMETER RawXML
        Raw path XML to parse
    .OUTPUTS
        Still figuring that out...
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

        if ($rawXml.PathResult.Result.innertext -like "*CLOSED*") {
            $table.add("Status", "No open paths found.")
            return [pscustomobject] $table
        } elseif ($null -ne $rawXml.PathResult.Message) {
            throw "No response found: $($rawXml.innerxml.tostring())"
        }

        $rawXml.PathResult.Paths.Path | foreach {
                
            $table = @{}
            $table.add("Status", "PathSegment")
            $table.add("PathID", $_.PathID)
            $table.add("Hops", $_.Hops)

            [pscustomobject] $table
         }
    }
}
