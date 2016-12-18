function Get-RSView {
    <#
    .SYNOPSIS
        Get all available views in RedSeal
    .OUTPUTS
        One custom object per view
#>
    [cmdletbinding()]
    Param(      
    )
    
    begin {
    }

    process {

        $uri = "https://$script:Server/data/view"
        
        Write-Debug "Query URI is $uri"

        #$viewXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $viewXml = Send-RSRequest -uri $uri
        
        $viewXml.list.view | foreach {

            [pscustomobject] @{ViewName = $_.name
                URL = $_.url
                PolicyEnabled = $_.policyEnabled
                Comments = $_.comments
            }
        }
    }
}
