function Get-RSSystemLicense {
    <#
    .SYNOPSIS
        Fetch the system license of the RedSeal Server
    .OUTPUTS
        A single system license object
    .PARAMETER xml
        Switch to return the raw XML response rather than a parsed object

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )

    begin {

        $uri = "https://" + $script:Server + "/data/system/license"

        #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials
        $resultXml = Send-RSRequest -uri $uri

        if ($XML) {
            $resultXml
        } else {

            [pscustomobject]@{
                State = $resultXml.LicenseInfoData.State
                LicenseExpirationDate = $resultXml.LicenseInfoData.LicenseExpiryDate
                MainteanceExpirationDate= $resultXml.LicenseInfoData.MaintenanceExpiryDate
                LicenseCount = $resultXml.LicenseInfoData.NumberofDeviceLicensed
                LicensesInUse = $resultXml.LicenseInfoData.CurrentDevicesInModel
                LicenseExceeded = [System.Convert]::ToBoolean($resultXml.LicenseInfoData.IsLicensedDeviceExceeded)
                Warnings = $resultXml.LicenseInfoData.Warnings
            }
        }
    }
}
