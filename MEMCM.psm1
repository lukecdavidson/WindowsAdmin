function Import-CMModule {
    $CMModule = Get-Module -Name "ConfigurationManager"
    $CMModuleFile = "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\ConfigurationManager.psd1"
    if ($null -eq $CMModule) {
        if ((Test-Path $CMModuleFile) -eq $true) {
            Import-Module $CMModuleFile
        } else {
            Write-Error "Configuration Manager Console not installed. Please install the console and try again."
            exit
        }
    }
}

function Add-BCAPC {
    <#
        .DESCRIPTION
        Adds a direct rule by computer name for the BCAPC Rolling Collection.

        .EXAMPLE
        Add-BCAPC -ComputerName 'GFM-MED-BCA01'
    #>

    Param(
        [string]$ComputerName
    )

    Import-CMModule

    $StartingDir = Get-Location
    Set-Location 001:\

    # Statically mapped collection id
    $BCACollectionId = '001002C2'

    $ResourceId = (Get-CMDevice -Name $ComputerName).ResourceId
    $ExistingRule = Get-CMDeviceCollectionDirectMembershipRule -CollectionId $BCACollectionId -ResourceId $ResourceId
    if ($null -eq $ExistingRule) {
        Add-CMDeviceCollectionDirectMembershipRule -CollectionId $BCACollectionId -ResourceId $ResourceId
    } else {
        Write-Host "Direct Rule already exists for computer $ComputerName, $ResourceId"
    }

    Set-Location $StartingDir
}

function Connect-CMRemote {
    <#
        .Description
        Connects to a computer using CmRcViewer.

        .EXAMPLE
        Connect-CMRemote TAS-ISD-SYS10

        .FORWARDHELPCATEGORY Alias
        cmr
    #>

    Param(
        # Computer to connect to
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        [string]
        $Computer
    )
    & 'C:\Program Files\YVFWC\RemoteToolsFramework\CmRcViewer.exe' $Computer
}

function Get-BCAPC {
    <#
        .DESCRIPTION
        Checks direct rules by computer name for the BCAPC Rolling Collection.

        .EXAMPLE
        Get-BCAPC -ComputerName 'GFM-MED-BCA01'
    #>

    Param(
        [string]$ComputerName
    )

    Import-CMModule

    $StartingDir = Get-Location
    Set-Location 001:\

    # Statically mapped collection id
    $BCACollectionId = '001002C2'

    $ResourceId = (Get-CMDevice -Name $ComputerName).ResourceId
    $ExistingRule = Get-CMDeviceCollectionDirectMembershipRule -CollectionId $BCACollectionId -ResourceId $ResourceId
    if ($null -eq $ExistingRule) {
        Write-Host "No Direct Rule for $ComputerName for BCAPC Collection"
    } else {
        Write-Host "Direct Rule found for $ComputerName"
        Write-Host $ExistingRule
    }

    Set-Location $StartingDir
}

function Get-CMUnDeployedApplications {
    <#
        .SYNOPSIS
        Gets applications in SCCM that do not have any deployments.

        .DESCRIPTION
        Uses Get-CMApplication to query the number of deployment for the application. Will also deserialzie the the application XML to 
        find the location of the content so it may be cleaned up.

        .EXAMPLE
        Get-CMUnDeployedApplications
    #>

    Import-CMModule

    $CMApplications = Get-CMApplication | Where-Object {$_.NumberOfDeployments -eq 0} | Sort-Object LocalizedDisplayName

    $OldApps = foreach ($Application in $CMApplications) {
        $Location = ([Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::DeserializeFromString($Application.SDMPackageXML)).DeploymentTypes[0].Installer.Contents.Location 
        $Application | Add-Member -MemberType NoteProperty -Name Location -Value $Location
        Write-Output $Application
    }


    $OldApps | select LocalizedDisplayName,NumberOfDeployments,NumberOfDependentDTs,NumberOfDependentTS,NumberOfDevicesWithApp,CreatedBy,DateCreated,DateLastModified
}

function Get-WorkstationUsers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]
        $Path = "$env:HOMEDRIVE$env:HOMEPATH\AppData\Local\Temp\Workstation Management-01A.csv",

        [Parameter(Mandatory=$false)]
        [switch]
        $Force
    )

    if ((Test-Path $Path) -eq $False -or $Force.IsPresent -eq $False) {
        $LastHour = (Get-Date).AddHours(-1)
        $LastWriteTime = Get-ChildItem $Path | Select-Object -Expand LastWriteTime
        if ($LastWriteTime -gt $LastHour) {
            Write-Error "Refusing to update. Last update less than 1 hour ago. Please pass -Force to override."
            exit
        }
    }

    Import-CMModule

    $StartingDir = Get-Location
    Set-Location 001:\

    Get-CMDevice -Fast | Select-Object Name,UserName,LastLogonUser | Export-Csv -NoTypeInformation -Path $Path
    Set-Location $StartingDir
}

function Install-CMApplication {
    <#
        .DESCRIPTION
        Installs an application from Software Center.

        .EXAMPLE
        Install-CMApplication -AppName 'JDXpert'

        .LINK
        Search-CMApplication
    #>

    Param(
        [string]$AppName,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $Application = Get-CimInstance -ComputerName $ComputerName -Namespace "root\ccm\ClientSDK" -Class CCM_Application | Where-Object {$_.Name -like "$AppName"} | Select-Object Id, Revision, IsMachineTarget
    $AppID = $Application.Id
    $AppRev = $Application.Revision
    $AppTarget = $Application.IsMachineTarget

    ([wmiclass]'ROOT\ccm\ClientSdk:CCM_Application').Install($AppID, $AppRev, $AppTarget, 0, 'Normal', $False) | Out-Null
}

function Invoke-CMClientActions {
    <#
        .DESCRIPTION
        Runs the Config Manager Client actions that are usually run from the Control Panel on a client computer. This will cause the device to check for a hardware inventory,
        software inventory, etc.

        .EXAMPLE
        Invoke-CMClientActions -ComputerName TAS-ISD-SYS10
    #>

    Param(
        # Computer to run client actions on. Defaults to the local machine
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [string]
        $ComputerName = $env:COMPUTERNAME
    )

    #A list of trigger schedules and what they kick off can be found here: https://docs.microsoft.com/en-us/mem/configmgr/develop/reference/core/clients/client-classes/triggerschedule-method-in-class-sms_client

    $TriggerSchedules =
    "00000000-0000-0000-0000-000000000021",
    "00000000-0000-0000-0000-000000000022",
    "00000000-0000-0000-0000-000000000003",
    "00000000-0000-0000-0000-000000000002",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000113",
    "00000000-0000-0000-0000-000000000114",
    "00000000-0000-0000-0000-000000000031",
    "00000000-0000-0000-0000-000000000121",
    "00000000-0000-0000-0000-000000000032",
    "00000000-0000-0000-0000-000000000010"

    foreach ($TriggerSchedule in $TriggerSchedules) {
        Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{$TriggerSchedule}"
    }
}

function Invoke-DPContentRedistribution {
    <#
        .DESCRIPTION
        Redistributes content to a distribution point if the content has failed to transfer. This script finds any content
        where the number of targed DPs does not equal the number of DPs that actually has the content. THIS SCRIPT ASSUMES THAT ALL
        CONTENT IDENTIFIED IS MISSING FROM THE SAME SPECIFIED DP! This is acceptable as this is likely the only use case for this script 
        (I.E. replaced the data drive on a DP).

        .EXAMPLE
        Invoke-DPContentRedistribution -DistributionPointFQDN "GV-GVM-CMDP.yvfwc.org" -SleepSeconds 180
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $DistributionPointFQDN,

        [Parameter(Mandatory=$false)]
        [integer]
        $SleepSeconds = 180
    )

    Import-CMModule

    $StartingDir = Get-Location
    Set-Location 001:\

    function Get-DistrubtionStatus {
        [CmdletBinding()]
        param (
            [Parameter()]
            [string]
            $PackageId
        )
        $NumInProgress = Get-CMDistributionStatus -Id $PackageId | Select-Object -Expand NumberInProgress
        if ($NumInProgress -eq 0) {
            Write-Host "Completed distribution."
            return 0
        } elseif ($NumInProgress -gt 0) {
            return 1
        }
    }

    if ($SleepDuration -le 180) {
        Write-Host "Please don't do that. Pick a number over 180 so we don't make the network team angry."
        exit
    }

    if ($null -eq (Get-CMDistributionPoint -Name "$DistributionPointFQDN")) {
        Write-Error -Message "Invalid distribution point. Please review and specify the Distribution Point FQDN."
        exit
    }


    $Packages = Get-CMDistributionStatus | Where-Object {$_.NumberSuccess -ne $_.Targeted}
    foreach ($Package in $Packages) {
        switch ($Package.ObjectTypeId) {
            2 { $Content = Get-CMPackage -Fast -Id $Package.PackageId }
            14 { $Content = Get-CMOperatingSystemUpgradePackage -PackageId $Package.PackageId }
            18 { $Content = Get-CMOperatingSystemImage -PackageId $Package.PackageId }
            19 { $Content = Get-CMBootImage -PackageId $Package.PackageId }
            24 { $Content = Get-CMSoftwareUpdateDeploymentPackage -PackageId $Package.PackageId }
            31 { $Content = Get-CMApplication -Name $Package.SoftwareName }
            Default { $Content = $null }
        }

        if ($null -ne $Content) {
            $Name = $Content | Select-Object -ExpandProperty Name
            if (($Content.Targeted - $Content.NumberSuccess) -gt 1){
                Write-Warning -Message "Content $Name has not been successfully distributed to more than one distribution point. This script will 
                distribute to $DistributionPointFQDN. However, distribition to other DPs must be handled seperately."
            }
            Write-Host "Distributing content $Name to $DistributionPointFQDN..."
	        Invoke-CMContentRedistribution -DistributionPointName "$DistributionPointFQDN" -InputObject $Content
            $Status = 1
            while ($Status) {
                Start-Sleep -Seconds $SleepSeconds
                $Status = Get-DistrubtionStatus -PackageId $Package.PackageId
            }
        } else {
            Write-Warning -Message "Content not found. Skipping..."
        }
    }

    Set-Location $StartingDir
}

function New-StiflerSubnet {
    <#
        .SYNOPSIS
        Creates new subnet in Stifler.

        .DESCRIPTION
        Creates a new Stifler subnet provided a LocationName and SubnetID. An input object containing multiple new subnets can also be input. After adding a subnet, please
        follow up and link the subnet to the correct parent. This can be done via the Web UI for Register-StiflerChildren command.

        .EXAMPLE
        New-StiflerSubnet -LocationName 'TMD-0020-SERVER' -Subnet '10.129.6.0' -GatewayMAC 'A8-46-9D-3C-95-72' -Description 'Toppenish Medical Dental - Server'

        .EXAMPLE
        $NewSubnets = Import-CSV -Path .\NewStiflerSubnets.csv
        New-StiflerSubnet -InputObject $NewSubnets

        .LINK
        Register-StiflerChildren
    #>

    Param(
        [Parameter(Mandatory,ValueFromPipeline, ParameterSetName = 'InputObject')]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$InputObject,

        # LocationName. Should match the VLAN name.
        [Parameter(Mandatory,ParameterSetName = 'LocationName')]
        [ValidateNotNullOrEmpty()]
        [string]$LocationName,

        # Network ID for subnet
        [Parameter(Mandatory,ParameterSetName = 'LocationName')]
        [ValidateNotNullOrEmpty()]
        [string]$Subnet,

        # MAC address for Gateway
        [Parameter(Mandatory,ParameterSetName = 'LocationName')]
        [string]$GatewayMAC,

        # Description
        [Parameter(Mandatory,ParameterSetName = 'LocationName')]
        [string]$Description
    )

    # If an object is passed, map the object's properties to the correct variables
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        $InputObject | ForEach-Object {
            Invoke-CimMethod -Namespace root\StifleR -ClassName Subnets -MethodName AddSubnet -Arguments @{LocationName=$_.LocationName;subnet=$_.Subnet;GatewayMAC=$_.GatewayMAC;Description=$_.Description}
        }
    } else {
        Invoke-CimMethod -Namespace root\StifleR -ClassName Subnets -MethodName AddSubnet -Arguments @{LocationName=$LocationName;subnet=$Subnet;GatewayMAC=$GatewayMAC;Description=$Description}
    }
}

function Search-WorkstationUsers {
    Param(
        # User to search
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity,

        # Path to WorksationList file generated by Get-WorkstationUsers
        [Parameter(Mandatory=$false)]
        [string]
        $Path = "$env:HOMEDRIVE$env:HOMEPATH\AppData\Local\Temp\Workstation Management-01A.csv"
    )

    if ((Test-Path $Path) -eq $False) {
        Write-Error "Workstation List not found at $Path. Please provide the correct path or generate the file with Get-WorkstationUsers"
        exit
    }

    Import-Csv $Path | Where-Object {$_.UserName -eq "$Identity" -or $_.LastLogonUser -eq "$Identity"}
}

function Register-StiflerChildren {
    <#
        .SYNOPSIS
        Links Stifler subnets to a parent

        .DESCRIPTION
        Searches for subnets using the sitecode. Finds subnets for that site that are not linked to a parent already and automatically links it
        to the parent. Parent is found by sorting for the subnet with the lowest network id.

        .EXAMPLE
        Register-StiflerChildren -SiteCode BHM
    #>

    Param(
        [string]$SiteCode
    )

    # Make sure the site code is valid
    $SiteCodes="AZE","AZW","BHM","BHT","CAD","CBD","CDC","CFH","CHC","CHV","DC1","DFK","DR","FMC","GFM","GMD","GNS","LFH","LHC","LMD","MCM","MEM","MFH","MHC","MHK",
    "MUA","MUB","MUC","MVF","MVW","NBG","NCA","NSH","PPD","RFH","RHG","RHL","SIC","SMC","TAC","TAN","TAS","TFW","TMD","UFD","UMA","UNE","UWC","VVM","YAK","YFM","YMD",
    "YPF","YPM","YPP","YTH","YVT"

    if ($SiteCodes -contains $SiteCode) {
        # Get current subnets that have a LocationName starting with the site code and sort them by the network ID IP
        $SiteSubnets=Get-CimInstance -Namespace root\StifleR -Query "select * from Subnets where LocationName LIKE ""$SiteCode%""" | Sort-Object {$_.subnetID -as [Version]}

        # Of those subnets, get the lowest to use as the "parent" container for the site
        $ParentGUID= $SiteSubnets | Select-Object -First 1 | Select-Object -ExpandProperty id

        # Children will be the left over subnets which aren't already linked to a parent
        $ChildrenSubnets=$SiteSubnets | Select-Object -Skip 1 | Where-Object LinkedWith -eq ""
        $ChildrenSubnets | ForEach-Object {Invoke-CimMethod -InputObject $_ -MethodName LinkWithSubnet -Arguments @{parentGUID="$ParentGUID"}}
    } else {
        Write-Error "Invalid site code: $SiteCode"
    }
}

function Search-CMApplication {
    <#
        .DESCRIPTION
        Searches for an application by name that would be available via Software Center.

        .EXAMPLE
        Search-CMApplication -AppName 'JDXpert'

        .LINK
        Install-CMApplication
    #>

    Param(
        [string]$AppName,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    (Get-CimInstance -ComputerName $ComputerName -ClassName CCM_Application -Namespace "root\ccm\clientSDK" | Where-Object {$_.Name -like "*$AppName*"})
}

function Unregister-StiflerChildren {
    <#
        .SYNOPSIS
        Unlinks all linked Stifler subnets associated with a site.

        .DESCRIPTION
        Searches for subnets using the sitecode. Finds subnets for that site that are linked to a parent and unlinks them. This may be useful if the incorrect subnet is configured
        as the parent and can be followed up with Register-StiflerChildren.

        .EXAMPLE
        Register-StiflerChildren -SiteCode BHM
    #>

    Param(
        [string]$SiteCode
    )

    # Make sure the site code is valid
    $SiteCodes="AZE","AZW","BHM","BHT","CAD","CBD","CDC","CFH","CHC","CHV","DC1","DFK","DR","FMC","GFM","GMD","GNS","LFH","LHC","LMD","MCM","MEM","MFH","MHC","MHK",
    "MUA","MUB","MUC","MVF","MVW","NBG","NCA","NSH","PPD","RFH","RHG","RHL","SIC","SMC","TAC","TAN","TAS","TFW","TMD","UFD","UMA","UNE","UWC","VVM","YAK","YFM","YMD",
    "YPF","YPM","YPP","YTH","YVT"

    if ($SiteCodes -contains $SiteCode) {
        $ChildrenSubnets=Get-CimInstance -Namespace root\StifleR -Query "select * from Subnets where LocationName LIKE ""%$SiteCode%""" | Where-Object LinkedWith -NE ""
        $ChildrenSubnets | ForEach-Object {Invoke-CimMethod -InputObject $_ -MethodName LinkWithSubnet -Arguments @{parentGUID=""}}
    } else {
        Write-Error "Invalid site code: $SiteCode"
    }
}

Set-Alias -Name updatewm -Value Get-WorkstationUsers
Set-Alias -Name wm -Value Search-WorkstationUsers
Set-Alias -Name cmr -Value Connect-CMRemote

Export-ModuleMember -Function * -Alias *