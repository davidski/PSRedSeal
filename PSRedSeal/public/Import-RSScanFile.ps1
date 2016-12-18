function Import-RSScanFile {
<#
    Import a vulnerability scan file into RedSeal
#>
    [cmdletbinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $True)]
        $FilePath,

        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $True)]
        $ScannerType = "nessus"

    )

    begin {
    }

    process {

        Write-Verbose "Working on file $FilePath"
        
        if (-not (Test-Path $FilePath)) {
            Write-Warning "Could not fine a file at $FilePath!"
            break
        }

        $uri = "https://$script:server/data/import/$ScannerType"
        
        Write-Verbose "Reading scan file..."
        $scanContent = [xml](get-content $FilePath)
        $scanContent = $scanContent.InnerXML.ToString().Replace("><",">`r`n<")
        Write-Verbose "Posting scan file..."

        $importResult = Send-RSRequest -Uri $uri -Method Post -Body $scanContent

        Write-Debug "Response is in importResult"

        $importResult.ImportResult

    }
}
