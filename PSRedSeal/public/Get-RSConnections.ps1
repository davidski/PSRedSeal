function Get-RSConnection {
    [pscustomobject]@{
        Server      = $script:Server
        Credentials = $script:Credentials
        APIVersion  = $Script:APIVersion
    }
}
