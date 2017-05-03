function Send-RSRequest {
    <#
    .SYNOPSIS
        Hack to allow selecting the desired version of the RedSeal API given the broken state of the Invoke-RestMethod cmdlet
    .PARAMETER uri
        URI to query
    .PARAMETER method
        HTTP method to use, defaults to GET
    .PARAMETER timeoutsec
        Number of seconds for timeout, defaults to 600 (10 minutes)
    .OUTPUTS
        Returns XML from the RedSeal server as an XML object
#>
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("GET", "DELETE", "HEAD", "PUT", "POST")]
        [string]
        $Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]
        $Body,

        [Parameter(Mandatory = $false)]
        [int]
        $TimeoutSec = (10*60)

    )

    # generate basic auth string
    $basicPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:Credentials.Password))
    $basicUsername = $script:Credentials.UserName
    $token = $basicUsername + ":" + $basicPassword
    $token = [Convert]::ToBase64String([Text.Encoding]::Ascii.GetBytes($token))

    #$webRequest.Credentials = $script:Credentials

    $webRequest = [System.Net.WebRequest]::Create( $uri )
    $webRequest.PreAuthenticate = $true
    $webRequest.Method = $method
    $webRequest.Headers.Add('Authorization', "Basic $token")
    $webRequest.Accept = 'application/x-RedSealv' + $script:APIVersion + '+xml'
    $webRequest.KeepAlive = $true
    $webRequest.UserAgent = "PowerShell-RedSeal"
    $webRequest.Timeout = ($TimeoutSec * 1000)


    #Write-Warning "Request is $webrequest"
    #Start-Sleep -Milliseconds 100

    if ($Method -eq 'PUT') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body) 
        #$webRequest.ContentType = $encoding
        $webRequest.ContentLength = $bytes.Length
        
        [System.IO.Stream] $outputStream = [System.IO.Stream]$Webrequest.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)  
        $outputStream.Close()
    } elseif ($method -eq 'POST') {

        #create a new GUID to serve as a multipart form boundary
        $boundary = [System.Guid]::NewGuid().ToString()

        #set the body of the HTTP post
        $respBody = @"
--$boundary
Content-Disposition: form-data; name="File"; filename="RSPoSH.xml"
$body
--$boundary--
"@

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($respbody) 
        $webRequest.ContentType = "multipart/form-data; boundary=" + $boundary
        $webRequest.ContentLength = $bytes.Length
        
        [System.IO.Stream] $outputStream = [System.IO.Stream]$Webrequest.GetRequestStream()
        $outputStream.Write($bytes, 0, $bytes.Length)  
        $outputStream.Close()
    }
    
    $errorMessage = $null
    try {
        $response = $webRequest.GetResponse()
    }
    catch [Net.WebException] {
        #$errorMessage = $Error[0].Exception.ToString()
        $ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message
        $Matched = ($ErrorMessage -match '[0-9]{3}')
        if ($Matched) {
            Write-Error -Message ('HTTP status code was {0} ({1})' -f $HttpStatusCode, $matched)
        } else {
            Write-Error -Message $ErrorMessage
        }

        Write-Error -Message $Error[0].Exception.InnerException.Response
        return
    }
    if (!$errorMessage) {
        $stream = $response.GetResponseStream()
        #$reader = new-object System.IO.StreamReader($response.GetResponseStream())
        $reader = [io.streamreader]($stream)
        [xml]$reader.ReadToEnd()
        $stream.flush()
        $stream.close()
    } else {
        Write-Warning "Error communicating with RedSeal: $errorMessage"
    }
}