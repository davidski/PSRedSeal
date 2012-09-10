function Read-RedSeal
{
    <#
.SYNOPSIS
    Reads RedSeal reports
.DESCRIPTION
    Reads RedSeal vulnerability reports and converts the RedSeal XML
into useable objects.
.Example
    Read-RedSeal https://<servername>/data/report/<reportname>
    Read-RedSeal -ReportURL https://<servername>/data/report/<reportname>
#>


    param(
    # The URL for the reports
    [Parameter(Mandatory=$true,Position=0)]
    [Uri]$ReportUrl,

    # The credential used to get the report
    [Parameter(Mandatory=$true,Position=1)]
    [Management.Automation.PSCredential]
    $Credential
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

        [Timespan]$Timeout = "0:45:0",
        [string]$UserAgent = "PowerShell RedSeal POC",
        [string]$Accept = "*/*"
        )

        $req = [Net.HTTPWebRequest]::Create($url)
        $bytes = [Text.Encoding]::UTF8.GetBytes($username+":" + $password)
        $authinfo = [Convert]::ToBase64String($bytes)
        $req.Headers.Add("Authorization", "Basic " + $authinfo)

        #Set timeout (ms) value for the web request, defined by how
long RedSeal takes to create the report
        $req.Timeout = $Timeout.TotalMilliSeconds

        $req.UserAgent = $UserAgent
        $req.Accept = $Accept

        #$req.ContentType = "text/html"
        $req.Method ="GET"
        $req.ContentLength = 0

        Write-Progress -Activity "Getting report" -Status "Sending
request and awaiting response"
        try {
            $resp = $req.GetResponse()
        } catch {
            $ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
            $Matched = ($ErrorMessage -match '[0-9]{3}')
            if ($Matched) {
                Write-Error -Message ('HTTP status code was {0} ({1})'
-f $HttpStatusCode, $matched);
            } else {
                Write-Error -Message $ErrorMessage;
            }

            Write-Error -Message $Error[0].Exception.InnerException.Response
            return
        }

        Write-Verbose "Reading response"
        $reader = new-object System.IO.StreamReader($resp.GetResponseStream())
        Write-Output $reader.ReadToEnd()

        #clean up
        $reader.close()

        $resp.close()

    }

        # This code reads specific XML elements from a stream using
XmlTextReader
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
        public static IEnumerable<string> LoadXml(Stream stream,
string[] element)
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

                            yield return "<" + reader.Name + ">" +
reader.ReadInnerXml() + "</" + elementName + ">" ;
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

                            yield return (reader.Name + "-" +
streamOffset.ToString() + "-" + stream.Position.ToString());
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
        $un = $credential.GetNetworkCredential().Username
        $pass = $credential.GetNetworkCredential().Password
        Write-Progress "Getting Report" "  "
        $httpResponse = Get-HTTP -Username $un -Password $pass -Url $ReportUrl
        Write-Progress "Creating Memory Stream" "  "
        $s = [IO.MemoryStream]([Text.Encoding]::UTF8.GetBytes($httpResponse))
        Write-Progress "Extracting MetaData" "  "
        $metaData = @($fastReadXml::LoadXml($s, "MetaData"))
        #$s.Close()
        #$s.Dispose()
        $null = $s.Seek(0, "Begin")
        $names = $metaData | foreach { ($_ -as [xml]).MetaData.Name }

        $rowInt = 0
        $perc = 0
        Write-Progress "Unwinding XML" "  "
        foreach ($object in $fastReadXml::LoadXml($s, "object-array")) {
            $xmlObject = [xml]$object
            $perc += 5
            if ($perc -gt 100) { $perc = 0 }
            Write-Progress -activity "Unwinding XML" -status
"Processing row $rowint" -percentcomplete $perc
            $values = $xmlObject |
                Select-Xml "//descendant::text()" |
                ForEach-Object { $_.Node.Value }
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

    }
}
