function Remove-RSHost {
    <#
    .SYNOPSIS
        Deletes a given host
    .PARAMETER TreeID
        RedSeal TreeID for a host object
    .PARAMETER Name
        DNS name of the host object
    .OUTPUTS
        Only a message
#>
    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID="2c9697a7316371660131f73d53b2593a",

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name="ppwsec05.childrens.sea.kids"
            
    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/host/$Name"
        } else {
            $uri = "https://$script:server/data/host/id/$TreeID"
        }
        Write-Verbose "Deleting host object."   
        #$hostXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -Method DELETE
        $hostXml = Send-RSRequest -uri $uri -Method DELETE

        Write-Verbose "Reponse from servers is $($hostXml.innerXML)"
        Write-Debug "Response from delete request is $($hostXml.innerXML)"

        if ($hostXml.message.text -like 'No computers*') {
            [pscustomobject] @{Message = "No host found"}
        } else {
            [pscustomobject] @{Message = "Deletion successful"}
        }

    }
}

