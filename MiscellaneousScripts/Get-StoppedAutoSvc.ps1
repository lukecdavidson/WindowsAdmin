<#
    .Description
    Gets services that are set to autostart but not running
#>

Get-Service | ForEach-Object {
    $StoppedAuto=[PSCustomObject]@{
        Status=$_.Status
        StartType=$_.StartType
        Name=$_.Name
        DisplayName=$_.DisplayName
    }
    Write-Output $StoppedAuto | Where-Object StartType -eq Automatic | Where-Object Status -eq Stopped
}