function Read-RSReport {
    <#
    .SYNOPSIS
        Reads RedSeal report
    .DESCRIPTION
        Reads RedSeal reports and converts the RedSeal XML into usable objects.
    .PARAMETER ReportName
        Name of the report to fetch and read
    .PARAMETER ReportFile
        Full path to file name to use in place of reading from RedSeal server
    .Example
        Read-RSReport Remediation+Priorities+%28Web+Report%29
        Read-RSReport -ReportName https://ppxsec04/data/report/All+Exposed+Vulnerabilities+with+Patches
        Read-RSReport -ReportFile C:\testReport.xml
#>

    [cmdletBinding(DefaultParameterSetName='ReportUrl')]
    param(
        # The URL for the reports
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = 'ReportURL')]
        [string]$ReportName,

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1, ParameterSetName = 'ReportURL')]
        [switch]$KeepTempFile = $false,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ReportFile', ValueFromPipelineByPropertyName = $true)]
        [Alias('Fullname')]
        [string]
        $File
    
    )

    begin {

    # Nesting this function
    function Get-HTTP {
        param(
            [Parameter(Mandatory=$true)]
            [string]$username,

            [Parameter(Mandatory=$true)][string]$password,
        
            #full URL to the RS report to fetch
            [Parameter(Mandatory=$true)][string]$url,

            [Timespan]$Timeout = "2:10:0",
        
            [string]$UserAgent = "PowerShell-RedSeal",
        
            [string]$Accept = "*/*"
        )

        $req = [Net.HTTPWebRequest]::Create($url)
        $bytes = [Text.Encoding]::UTF8.GetBytes($username + ":" + $password)
        $authinfo = [Convert]::ToBase64String($bytes)
        $req.Headers.Add("Authorization", "Basic " + $authinfo)

        #Set timeout (ms) value for the web request, defined by how long RedSeal takes to create the report
        $req.Timeout = $Timeout.TotalMilliSeconds

        $req.UserAgent = $UserAgent
        $req.Accept = $Accept

        #$req.ContentType = "text/html"
        $req.Method ="GET"
        $req.ContentLength = 0

        Write-Progress -Activity "Getting report" -Status "Sending request and awaiting response"
        try {
            $resp = $req.GetResponse()
        } catch {
            $ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
            $Matched = ($ErrorMessage -match '[0-9]{3}')
            if ($Matched) {
                Write-Error -Message ('HTTP status code was {0} ({1})' -f $HttpStatusCode, $matched)
            } else {
                Write-Error -Message $ErrorMessage
            }

            Write-Error -Message $Error[0].Exception.InnerException.Response
            return
        }

        Write-Verbose "Creating response stream"
        $reader = new-object System.IO.StreamReader($resp.GetResponseStream())

        write-Verbose "Reading response stream..."
        #Write-Output $reader.ReadToEnd()

        #dump the web response stream to a temporary file
        $tempFile = [IO.Path]::GetTempFileName()
        write-verbose "Writting response to $tempFile"
        $writer = new-object System.IO.StreamWriter($tempFile)
        $s = $reader.ReadLine()
        While ($null -ne $s) {
            $writer.WriteLine($s)
            $s = $reader.ReadLine()
        }
        $writer.close()
        write-verbose "$tempFile complete."

        #return the name of the temporary file
        $tempFile

        #clean up
        $reader.close()
        $resp.close()

    }

    # This code reads specific XML elements from a stream using XmlTextReader
    # (for speed and memory consumption)
    $fastReadXml = Add-Type -PassThru -ReferencedAssemblies System.Xml @"
using System;
using System.IO;
using System.Xml;
using System.Collections;
using System.Collections.Generic;

namespace FastImport {

    public class FastImportXml$(Get-Random)
    {
        public static IEnumerable<string> LoadXml(Stream stream, string[] element)
        {
            Hashtable matchingElements = new Hashtable();
            foreach (string elementName in element) {
                matchingElements.Add(elementName, elementName);
            }
            string matchStart = String.Empty;
            XmlTextReader reader =  new XmlTextReader(stream);
            StreamReader streamReader = new StreamReader(stream);
            XmlNodeType lastType;
            bool inElement = false;
            long streamOffset = 0;

            while (reader.Read()) {
                if (reader.NodeType == XmlNodeType.Element) {

                    if (! inElement) {
                        string elementName = reader.Name;
                        if (matchingElements.ContainsKey(elementName))  {

                            yield return "<" + reader.Name + ">" + reader.ReadInnerXml() + "</" + elementName + ">" ;
                            streamOffset = stream.Position;
                            matchStart = reader.Name;
                            continue;
                        }
                    }
                    if (inElement) {

                        // yield return reader.Name;
                    }

                } else if (reader.NodeType == XmlNodeType.EndElement) {
                    if (matchingElements.ContainsKey(reader.Name))  {
                        if (reader.Name == matchStart) {
                            inElement = false;

                            yield return (reader.Name + "-" + streamOffset.ToString() + "-" + stream.Position.ToString());
                        }
                    }
                }

                lastType = reader.NodeType;

            }
        }
    }
}
"@ |
    Select-Object -First 1
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ReportUrl') {
            
            Write-Progress -Activity "Getting Report" -Status "Report will be saved to the system temp directory"
            $un = $script:credentials.GetNetworkCredential().Username
            $pass = $script:credentials.GetNetworkCredential().Password
            [uri]$ReportUrl = "https://$script:server/data/report/$reportName"
            $httpResponse = Get-HTTP -Username $un -Password $pass -Url $ReportUrl

            Write-Progress -Activity "Creating Memory Stream" -Status "Reading in $httpResponse"        
            $s = [IO.File]::OpenRead($httpResponse)
            #$s = [IO.MemoryStream]([Text.Encoding]::UTF8.GetBytes($httpResponse))

        } elseif ($PSCmdlet.ParameterSetName -eq 'ReportFile') {
            $resolvedFile = $ExecutionContext.SessionState.Path.GetResolvedPSPathFromPSPath($file)
            if (-not $resolvedFile) { return }
            $s = [IO.File]::OpenRead("$resolvedFile")
        }

        Write-Progress "Searching for MetaData stanzas" "  "
        #extract each MetaData stanza
        #Performance issue: we read all the way to the end of the file, looking for metadata stanzas
        $metaData = @($fastReadXml::LoadXml($s, "MetaData"))
        
        $null = $s.Seek(0, "Begin")
        $names = $metaData | foreach { ($_ -as [xml]).MetaData.Name }

        $rowInt = 0
        $perc = 0
        Write-Progress "Unwinding XML" "  "
        foreach ($object in $fastReadXml::LoadXml($s, "object-array")) {
            $xmlObject = [xml]$object
            $perc += 5
            if ($perc -gt 100) { $perc = 0 }
            Write-Progress -activity "Unwinding XML" -status "Processing row $rowint" -percentcomplete $perc
            
            #We use the SelectChildren method to ensure that empty columns are also returned
            $values = $xmlObject."object-array".CreateNavigator().SelectChildren('Element').Value
            #$values = $xmlObject |
            #    Select-Xml "//descendant::text()" |
            #    ForEach-Object { $_.Node.Value }
            
            $table = @{}
            $nc = 0
            foreach ($n in $names) {
                $table[$n] = $values[$nc]
                $nc++
            }
            New-Object PSObject -Property $table

            $rowInt++
        }
        $s.Close()
        $s.Dispose()

        #If we're working off the server, clear out the temporary file
        if ($PSCmdlet.ParameterSetName -eq 'ReportUrl') {
            if ($keepTempFile) {
                Write-Verbose "Keeping $httpResponse per request"
            } else {
                Remove-Item $httpResponse
            }
        }


    }
}
