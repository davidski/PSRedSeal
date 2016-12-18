function Set-RSDataQuery {
    <#
    .SYNOPSIS
        Sets a RS Data Query object (RS 6.6+ API)
    .PARAMETER Group
        Group path to filter/group results
    .PARAMETER QueryType
        Type of DataQuery to run
    .PARAMETER QueryTarget
        Host or subnet information
    .PARAMETER QueryFilter
        ID, Name, or IP of the QueryTarget
    .PARAMETER XML
        Return raw XML
    .PARAMETER TimeoutSec
        HTTP timeout value
    .OUTPUTS
        A DataQuery XML blob
    #>
    [cmdletbinding(SupportsShouldProcess = $true)]
    Param()
}
