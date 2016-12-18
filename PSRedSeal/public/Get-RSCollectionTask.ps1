function Get-RSCollectionTask {
    <#
    .SYNOPSIS
        Retrieve the list of data collection tasks.
    .OUTPUTS
        One custom object per data collection task.
#>
    [cmdletbinding()]
    Param(  
    )

    begin {
        $uri = "https://$script:server/data/import/task"
    }

    process {
      
        Write-Verbose "Fetching data collection tasks."
        $tasksXml = Send-RSRequest -uri $uri

        Write-Debug "XML returned is at tasksXml.list"

        $tasksXml.list.DataCollectionTask | foreach {
            [pscustomobject] @{
                Name           = $_.Name
                URL            = $_.URL
                Created        = ConvertFrom-RSDate $_.Created
                Type           = $_.Type
                Enabled        = [boolean]$_.enabled
                Schedule       = $_.schedule
                SendEmail      = [boolean]$_.SendEmail
                RuleUsage      = [boolean]$_.RuleUsage
                DynamicRouting = [boolean]$_.DynamicRouting
                PluginName     = $_.Plugin.Name
                PluginVersion  = $_.Plugin.Version
                Hostname       = if ($_.communication."properties".property.name -contains "Hostname") { 
                    "hostname present"  } else { 
                    $null }
            }
        }
    }
}
