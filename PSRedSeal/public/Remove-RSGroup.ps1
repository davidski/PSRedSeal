function Remove-RSGroup {
    <#
    .SYNOPSIS
        Removes a group within RedSeal
    .PARAMETER GroupPath
        Path to group to remove
    .PARAMETER XML
        Boolean switch to return the raw XML instead of a parsed object
    .OUTPUTS
        Nothing.
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [String]
        $GroupPath,
   
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )
    
    begin {
    }

    process {

        $uri = "https://" + $script:Server + "/data/group" + $groupPath
        
        Write-Debug "Query URI is $uri"

        #$groupXml = Invoke-RestMethod -Uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $groupXml = Send-RSRequest -uri $uri -Method DELETE

        Write-Debug "Response is $($groupXml.InnerXML.tostring())"

        if ($XML) {
            $groupXml
        } else {
            $groupXml
        }
    }
}
