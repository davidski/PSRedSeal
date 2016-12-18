function ConvertTo-RSDate {
    <#
    .SYNOPSIS
        Converts from .NET datetime object to RedSeal timezone date
    .PARAMETER RSDate
        .NET datetime object
    .OUTPUTS
        A RedSeal datetime string
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [DateTime]
        $RSDate
    )

    process {

        Write-Verbose "Received a raw date of $RSDate"

        if ($null -ne $RSDate) {
            $RSDate =  $RSDate | Get-Date -Format "MMM dd, yyyy hh:mm:ss tt PST"
        } else {
            $RSDate =  Get-Date -Format "MMM dd, yyyy hh:mm:ss tt PST"
        }

        $RSDate

    }
}
