$CustomPath = "$env:USERPROFILE\Scripts", "$env:USERPROFILE\Software"
foreach ($PathDir in $CustomPath) {
    if (Test-Path $PathDir) {
        $env:Path += ";$PathDir"
    }
}

$LocalFolder = "$env:USERPROFILE"
$ModulePath = "Documents\WindowsPowerShell\Modules"
$EnableModules = "MEMCM.psm1", "mytools.psm1"

function Enable-PSModules {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter(Mandatory=$true)]
        [array]
        $ModuleList
    )

    foreach ($Module in $ModuleList) {
        Import-Module "$Path\$Module"
    }
}

if (Test-Path "$LocalFolder\$ModulePath\MyTools") {
    Enable-PSModules -Path "$LocalFolder\$ModulePath\MyTools" -ModuleList $EnableModules
}
