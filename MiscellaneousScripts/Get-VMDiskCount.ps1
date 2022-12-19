Connect-VIServer dc-inf-vcenter2,dr-inf-vcenter2,ykm-rxcf-vcenter2
$VMList = Get-VM | Select-Object -ExpandProperty Guest | Where-Object GuestFamily -eq "windowsGuest"

$VMs = @()

foreach ($VM in $VMList) {
    $DiskList = $VM.Disks.Path
    $VM | Add-Member -MemberType NoteProperty -Name 'DiskList' -Value $DiskList
    $VM = $VM | Select-Object VMName, State, DiskList
    $VMs += $VM
}

Export-Csv -Path .\VMDiskCount.csv -InputObject $VMs