function Get-RSReportList {
    <#
    .SYNOPSIS
        Gets available RedSeal reports
    .DESCRIPTION
        Gets all available RedSeal reports
    .OUTPUTS
        One report object per visible report.
#>
    [cmdletbinding()]
    Param(
    
    )

    begin {
    }

    process {
 
        #$reportListXml = Invoke-RestMethod -Uri "https://$script:server/data/reports" -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $reportListXml = Send-RSRequest -Uri "https://$script:server/data/reports"

        $reportListXml.List.Report | ForEach-Object {
            [pscustomobject] @{
                Name         = $_.Name
                Description  = $_.Description
                DesignFile   = $_.DesignFIle
                Owner        = $_.Owner
                LastEditor   = $_.LastEditor
                ModifiedDate = ConvertFrom-RSDate $_.ModifiedDate
                ReportURL    = $_.URL
             }
         }

    }
}
