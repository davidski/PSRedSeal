function Get-RSModelIssue {
<#
    Gets the status of one or more model issue checks
#>
    [cmdletbinding()]
    Param(

        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $True)]
        $IssueID

    )

    begin {
    }

    process {

        Write-Verbose "Working on issue #: $($IssueID)"
        
        $uri = "https://$script:server/data/library/MI/$issueID"
        Write-Verbose "uri is $uri"
        $miResult = Send-RSRequest -Uri $uri -Method GET -TimeoutSec 10

        Write-Debug "Response is in miResult"

        $miResult.ModelIssue.Issues.IssueSummary.FailedHosts.Host | % { [pscustomobject]@{
                        TreeID           = $_.TreeID
                        Hostname         = $_.Name
                        IPAddress        = $_.Address
                        PrimaryCapability = "HOST"
                        }
         }

    }
}
