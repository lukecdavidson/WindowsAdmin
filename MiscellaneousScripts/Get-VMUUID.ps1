Param(
    # Computer to get VM UUID of
    [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
    [string]
    $ComputerName
)

$UUID = Get-VM -Name $ComputerName | %{(Get-View $_.Id).config.uuid}
$UUID = $UUID -replace '[-]'
for ($i=2; $i -le 45; $i=$i+3) {
    $UUID = $UUID.Insert($i, ' ')
}
Write-Output "VMware-$UUID"