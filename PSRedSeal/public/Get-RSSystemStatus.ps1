function Get-RSSystemStatus {
    <#
    .SYNOPSIS
        Fetch the system status of the RedSeal Server
    .OUTPUTS
        A single system status object
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )

    begin {

        $uri = "https://" + $script:Server + "/data/system"

        #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials
        $resultXml = Send-RSRequest -uri $uri

        if ($XML) {
            $resultXml
        } else {

            [pscustomobject]@{
                LastAnalysisStatus = $resultXml.SystemStatus.LastAnalysis.Status
                LastAnalysisStartTime = $resultXml.SystemStatus.LastAnalysis.StartTime | ConvertFrom-RSDate
                LastAnalysisEndTime = $resultXml.SystemStatus.LastAnalysis.EndTime | ConvertFrom-RSDate
                RunningAnalysisStatus = $resultXml.SystemStatus.RunningAnalysis.Status
                RunningAnalysisStatusStartTime = $(if ($null -ne $resultXml.SystemStatus.RunningAnalysis.StartTime ) {
                    ConvertFrom-RSDate $resultXml.SystemStatus.RunningAnalysis.StartTime
                    })
                RunningAnalysisStatusPercentComplete = $resultXml.SystemStatus.RunningAnalysis.PercentComplete
                RunningAnalysisStatusStage = $resultXml.SystemStatus.RunningAnalysis.Name
                TRLVersion = $resultXml.SystemStatus.TRLVersion
                RedSealVersion = $(if ($null -ne $resultXml.SystemStatus.RedSealVersion) {
                    $resultXml.SystemStatus.RedSealVersion } else {
                    "RedSeal 6.0 (Build unknown)" })
                HardDiskSummary = $(if ($null -eq $resultXml.SystemStatus.RedSealVersion) {
                    $null } else {
                    [pscustomobject]@{
                        DiskUtilization = [int]$resultXML.SystemStatus.HardDiskSummary.DiskUtilization
                        RaidDiskStatus = $resultXML.SystemStatus.HardDiskSummary.RaidDiskStatus
                        TotalSpace = [int]$resultXML.SystemStatus.HardDiskSummary.TotalSpace
                        FreeSpace = [int]$resultXML.SystemStatus.HardDiskSummary.FreeSpace                        
                        EstimatedBackupSizeWithAnalysis = [int]$resultXML.SystemStatus.HardDiskSummary.EstimatedBackupSizeWithAnalysis
                        EstimatedBackupSizeWithoutAnalysis = [int]$resultXML.SystemStatus.HardDiskSummary.EstimatedBackupSizeWithoutAnalysis
                     }
                 })
            }
        }
    }
}
