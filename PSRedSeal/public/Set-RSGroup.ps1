function Set-RSGroup {
    <#
    .SYNOPSIS
        Sets or creates a group within RedSeal
    .PARAMETER Group
        Group object to set in RedSeal
    .PARAMETER XML
        Boolean switch to return the raw XML instead of a parsed object
    .OUTPUTS
        Nothing.
#>
    [cmdletbinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [PSObject]
        $Group,
   
        [Parameter(Mandatory = $false)]
        [Int]
        $TimeoutSec = 60 * 2,

        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )
    
    begin {
    }

    process {

        $groupXML = New-Object XML
        $e = $groupXml.CreateElement("FullGroup")
        $groupXml.AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Name")
        $e.innertext = $group.GroupName
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Path")
        $e.innertext = $group.GroupPath
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Comments")
        $e.innertext = $group.Comments
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Membership")
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        #build list of static hosts to add
        if ($group.Hosts.Count) {
            $e = $groupXml.CreateElement("StaticComputers")
            $groupXml.SelectSingleNode("/FullGroup/Membership").AppendChild($e) | Out-Null
            foreach ($hostObj in $group.hosts) {

                $e = $groupXml.CreateElement("Host")
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Name")
                $e.innertext = $hostObj.name
                #$groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers").AppendChild($e) | Out-Null
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers/Host[last()]").AppendChild($e) | Out-Null

                <#
                $e = $groupXml.CreateElement("Host")
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("TreeID")
                $e.innertext = $hostObj.TreeID
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers/Host[last()]").AppendChild($e) | Out-Null
                #>
            }
        }

        #build list of static subnets to add
        if ($group.Subnets.Count) {
            $e = $groupXml.CreateElement("StaticSubnets")
            $groupXml.SelectSingleNode("/FullGroup/Membership").AppendChild($e) | Out-Null
            foreach ($subnet in $group.Subnet) {
                $e = $groupXml.CreateElement("Subnet")
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticSubnets").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Name")
                $e.innertext = $subnet.id
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticSubnets/Subnet[last()]").AppendChild($e) | Out-Null
            }
        }

        #build any reference pointers
        if ($group.References.Count) {
            $e = $groupXml.CreateElement("Groups")
            $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null
            foreach ($reference in $group.References) {
                
                # create contained for the group
                $e = $groupXml.CreateElement("FullGroup")
                $groupXml.SelectSingleNode("/FullGroup/Groups").AppendChild($e) | Out-Null

                #set the parent group
                $e = $groupXml.CreateElement("Name")
                $e.innertext = $reference.Name
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("URL")
                $e.innertext = $reference.URL
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Path")
                $e.innertext = $reference.Path
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]").AppendChild($e) | Out-Null
            
                #set the target info
                $e = $groupXml.CreateElement("ReferencedGroup")
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Name")
                $e.innertext = $reference.TargetName
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]/ReferencedGroup").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("URL")
                $e.innertext = $reference.TargetURL
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]/ReferencedGroup").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Path")
                $e.innertext = $reference.TargetPath
                $groupXml.SelectSingleNode("/FullGroup/Groups/FullGroup[last()]/ReferencedGroup").AppendChild($e) | Out-Null
            }
        }

        
        Write-Debug $groupXML.InnerXML.ToString().Replace("><",">`r`n<")

        #set the body of the HTTP put
        $respBody = $($groupXml.InnerXML.ToString().Replace("><",">`r`n<"))

        Write-Verbose "Query put body is: $respBody"

        $uri = "https://$script:server/data/group"
        Write-Verbose "URI is $uri"

        #finally, try to execute the query
        try {
            #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -Method Put -Body $respBody -TimeoutSec $timeoutSec -DisableKeepAlive
            $resultXml = Send-RSRequest -uri $uri -Method Put -Body $respBody
        }
        catch {
            throw $_.Exception.Message
        }

        Write-Debug $resultXml.innerxml.tostring()
        #$resultXml        

    }
}
