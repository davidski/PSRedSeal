function Get-RSAdminTaskHistory {
<#
    Retrieves task history
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$XML = $false
    )

    begin {
    }

    process {

        $uri = $uri = 'https://' + $script:Server + '/data/system/adminoperation'
        $response = Send-RSRequest -Uri $uri -Method GET

        if ($XML) {
            $response
        } else {
            #parse the response
            if ($response.message) {
                $response.message
            } else {
                #emit parsed object
                foreach ($taskObj in $response.list.AsyncTaskTrackerData) {
                    [pscustomobject]@{
                        URL          = $taskObj.URL
                        ID           = $taskObj.ID
                        Description  = $taskObj.Description
                        Finished     = [boolean]$taskObj.IsTaskFinished
                        CompletionPercentage = $taskObj.CompletionPercentage
                        JobStateInfo = $taskObj.Status
                        TextStatus   = $taskObj.TextStatus
                        TimeQueued   = ConvertFrom-RSDate $taskObj.QueueTime
                        BeginTime    = ConvertFrom-RSDate $taskObj.StartTime
                        EndTime      = ConvertFrom-RSDate $taskObj.EndTime
                        Error        = $taskObj.Exception
                        Result       = $taskObj.Result
                    }
                }
            }
        }   
    }
}
