function ConvertFrom-RSDate {
    <#
    .SYNOPSIS
        Converts from RedSeal timezone date to a .NET datetime object
    .PARAMETER RSDate
        RedSeal SQL date string
    .OUTPUTS
        A .NET datetime object
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [String]
        $RSDate
    )

    process {

        Write-Verbose "Received a raw date of $RSDate"

        if ($null -ne $RSDate) {
            $RSDate =  $RSDate -replace "\s\w{3}$", ""
            [datetime]::ParseExact($RSDate, "MMM d, yyyy h:mm:ss tt", $null)
        }

    }
}
