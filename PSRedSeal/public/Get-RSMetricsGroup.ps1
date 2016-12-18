function Get-RSMetricsGroup {
<#
    Parses a single metrics query group
#>
    [cmdletbinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $True)]
        $DataQueryResults

    )

    begin {
    }

    process {

        Write-Verbose "Working on $($DataQueryResults.Path.ToString())"
        
        foreach ($metricObject in $DataQueryResults.Results.Metrics) {
            Get-RSMetricsDetail -QueryLeaf $metricObject -GroupPath $DataQueryResults.Path.ToString()
        }
        if ($DataQueryResults.Groups) {
            foreach ($group in $DataQueryResults.groups.group) {
                Get-RSMetricsGroup $group
            }
        }
    }
}
