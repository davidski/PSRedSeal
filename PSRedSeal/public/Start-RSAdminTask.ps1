function Start-RSAdminTask {
<#
    Initiates an administrative task
#>
    [cmdletbinding()]
    Param(
        
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $True)]
        [ValidateSet("Backup", "Restore", "PluginUpload", "ImageSetNext", "ImageDelete", "RebootAppliance")]        
        $TaskType

    )

    begin {
    }

    process {

        $taskXml = New-Object XML

        $decl = $taskXml.CreateXmlDeclaration("1.0", $null, $null)
        $decl.Encoding = "ISO-8859-1"
        $taskXml.InsertBefore($decl, $taskXml.DocumentElement) | Out-Null
        
        $e = $taskXml.CreateElement("AdminOperationCommand")
        $taskXml.AppendChild($e) | Out-Null
        
        $e = $taskXml.CreateElement("Action")
        $e.innertext = $TaskType
        $taskXml.SelectSingleNode("/AdminOperationCommand").AppendChild($e) | Out-Null
        
        #ImageSetNext sepcific (hardcoded ATM)
        $e = $taskXml.CreateElement("ImageName")
        $e.innertext = "RedSeal 6.6.1 (Build-374)"
        $taskXml.SelectSingleNode("/AdminOperationCommand").AppendChild($e) | Out-Null
   
        $reqBody = $taskXml.innerxml.ToString().Replace("><", ">`r`n<")

        $uri = 'https://' + $script:Server + '/data/system/adminoperation'
    
        Write-Verbose "Request is: $reqBody"

        $response = Send-RSRequest -Method PUT -Body $reqBody -Uri $uri

        $response
    
    }
}
