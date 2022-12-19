Import-Csv .\OptionsToDelete.csv | ForEach-Object {
    Remove-DhcpServerv4OptionValue -ComputerName DC-INF-DC1 -ScopeId $($_.ScopeId) -OptionId $($_.Option) -confirm:$False
}