function Connect-RSServer {
    <#
    .SYNOPSIS
        Set connection parameters for the RedSeal cmdlets
    .OUTPUTS
        None
#>
    Param(
    
        [Parameter(Mandatory=$false, Position = 0)]
        [string]
        $Server,

        [Parameter(Mandatory=$false, Position = 1)]
        [PSCredential]
        $Credentials
    )

    if ($PSBoundParameters.ContainsKey("Server")) {
        $script:Server = $Server
    }

    #if a credential has not been pased or previously defined, mandate that one be specified
    if ($PSBoundParameters.ContainsKey("Credentials")) {
        $script:Credentials = $Credentials
    } elseif ($script:Credentials -isnot [pscredential]) {
        $script:Credentials = Get-Credential -Message "Enter credentials for the RedSeal server"
    }

    $uri = "https://" + $script:Server + "/data/system"
    if (![xml](Send-RSRequest -uri $uri -Method HEAD)) {
        $script:Credentials = $null
        Throw "Unable to connect to RedSeal!"
    }

    if ((Get-RSSystemStatus).RedSealVersion -notlike '*7.*') {
        $script:APIVersion = "6.0"
        Write-Warning "Compatibility with RedSeal pre-7.0 API deprecated and no longer tested!"
    } else {
        $script:APIVersion = "7.0"
    }

}
