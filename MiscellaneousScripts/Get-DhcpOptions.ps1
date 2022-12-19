<#
    .Description
    Gets values for non-guest DHCP scopes given an OptionId.

    .EXAMPLE
    Get-DhcpScopeOptions -OptionId 42
#>

Param([string]$OptionId)

$Scopes=Get-DhcpServerv4Scope -ComputerName DC-INF-DC1 | Where-Object Name -NotLike '*GUEST*'

foreach ($Scope in $Scopes) {
    $Options=Get-DhcpServerv4OptionValue -ComputerName DC-INF-DC1 -ScopeId $Scope.ScopeId | Where-Object OptionId -eq $OptionId
    $ScopeOption = [PSCustomObject]@{
        ScopeId = $Scope.ScopeId
        Name = $Scope.Name
        OptionId = $Options.OptionId
        OptionValue = $Options.Value
    }
    Write-Output $ScopeOption | Where-Object OptionId -NotLike $null
}