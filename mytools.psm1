function Set-DefaultDisplaySet {
    <#
        .Description
        Sets the default display set for object output.
    #>

    Param (
        [Parameter(Mandatory=$true)]
        [hashtable]
        $DefaultDisplaySet,

        [Parameter(Mandatory=$true)]
        [object]
        $Object
    )

    $DefaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$DefaultDisplaySet)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($DefaultDisplayPropertySet)
    $Object | Add-Member MemberSet PSStandardMembers $PSStandardMembers

    return $Object
}

function Connect-Azure {
    <#
        .Description
        Connects to AzureAD. Used in conjunction with other scripts where authentication to Azure AD is needed.
    #>

    Write-Warning 'Azure AD authentication needed.'
    $Question = 'Connect to Azure AD via Connect-AzureAD?'
    $Choices  = '&Yes', '&No'

    $Decision = $Host.UI.PromptForChoice($Title, $Question, $Choices, 1)

    if ($Decision -eq 0) {
        Connect-AzureAD > $null
        return 0
    } else {
        Write-Host 'Azure AD connection aborted.'
        return 1
    }
}

function Get-User {
    <#
        .Description
        Gets an AD User and prints out useful information in a clear format.

        .EXAMPLE
        Get-User luked

        .FORWARDHELPCATEGORY Alias
        user
    #>

    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity
    )

    $User = Get-ADUser -Identity $Identity -Properties *
    $Subordinates = (Get-ADUser -Filter "Manager -eq '$User'").Name
    $User | Add-Member -Type NoteProperty -Value $Subordinates -Name Subordinates

    $DefaultDisplaySet = 'DisplayName', 'Title', 'Department', 'physicalDeliveryOfficeName', 'Manager', 'Subordinates', `
      'telephoneNumber', 'Mail', 'whenCreated', 'DistinguishedName', 'Subordinates'
    $User = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $User

    return $User
}

function Get-UserGroups {
    <#
        .Description
        Gets an AD User's group membership.

        .EXAMPLE
        Get-UserGroups luked

        .FORWARDHELPCATEGORY Alias
        groups
    #>

    Param(
        # User AD Identity
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity,

        # Output as object
        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false)]
        [string]
        $Output
    )

    $User = Get-ADUser -Identity $Identity -Properties memberOf
    $Groups = $User.memberOf | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object
    $User | Add-Member -Type NoteProperty -Name Groups -Value $Groups

    $DefaultDisplaySet = 'Groups'
    $User = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $User

    return $User
}

function Compare-UserGroups {
    <#
        .Description
        Compares group membership between two AD users.

        .EXAMPLE
        Compare-UserGroups luked luiso

        .FORWARDHELPCATEGORY Alias
        groupdiff
    #>

    Param(
        # User AD Identity1
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity1,

        # User AD Identity2
        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [string]
        $Identity2
    )

    $User1 = Get-ADUser -Identity $Identity1 -Properties memberOf | Select-Object -ExpandProperty memberOf
    $Groups1 = $User1.memberOf | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object
    $User1 | Add-Member -Type NoteProperty -Name Groups -Value $Groups1

    $User2 = Get-ADUser -Identity $Identity2 -Properties memberOf | Select-Object -ExpandProperty memberOf
    $Groups2 = $User2.memberOf | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object
    $User2 | Add-Member -Type NoteProperty -Name Groups -Value $Groups2

    $Diff = Compare-Object $User1 $User2 -Property Groups, memberOf

    $DefaultDisplaySet = 'Groups'
    $Diff = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $Diff

    return $Diff
}

function Get-UserAADGroups {
    <#
        .Description
        Gets a user's group membership from Azure AD. This may be useful to determine if an addition to a group has been synced to Azure AD yet.

        .EXAMPLE
        Get-UserAADGroups luked

        .FORWARDHELPCATEGORY Alias
        aadgroups
    #>

    Param(
        # User AD Identity
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity,

        # Output as object
        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false)]
        [string]
        $Output
    )

    function Get-AzureADUserGroup {
        $User = Get-AzureADUser -SearchString "$Identity@yvfwc.org" | Get-AzureADUserMembership
        switch ($Output) {
            short { $User | Select-Object -ExpandProperty DisplayName }
            object { Write-Output $User }
            Default { $User | Select-Object -ExpandProperty DisplayName }
        }
    }

    try {
        Get-AzureADUserGroup
    }
    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        $Connect = Connect-Azure
        if ($Connect -eq 0) {Get-AzureADUserGroup}
    }
}

function Get-UserName {
    <#
        .Description
        Gets a user's AD user name by searching using their name. Search will search via the DisplayName property.

        .EXAMPLE
        Get-UserName "Luke Davidson"

        .FORWARDHELPCATEGORY Alias
        name

    #>
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity
    )
    $Users = Get-ADUser -Filter "DisplayName -like '*$Identity*'"

    $DefaultDisplaySet = 'DisplayName', 'Name', 'Enabled', 'LockedOut', 'PasswordExpired', 'PasswordLastSet', `
      'LastBadPasswordAttempt', 'LastLogonDate', 'Modified', 'DistinguishedName'
    $Users = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $Users

    return $Users
}

function Get-UserPWInfo {
    <#
        .Description
        Gets a user's AD account and prints information useful for troubleshooting common password issues.

        .EXAMPLE
        Get-UserPWInfo luked

        .FORWARDHELPCATEGORY Alias
        pw
    #>

    Param(
        # Active Directory Identity for user
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity
    )

    $User = Get-ADUser -Identity $Identity -Properties *

    $DefaultDisplaySet = 'DisplayName', 'Name', 'Enabled', 'LockedOut', 'PasswordExpired', 'PasswordLastSet', `
      'LastBadPasswordAttempt', 'LastLogonDate', 'Modified', 'DistinguishedName'
    $User = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $User

    return $User
}

function Connect-PS {
    <#
        .Description
        Enters a PS Session to a remote computer. Will use IA account if OperatingSystem contains 'Server'

        .EXAMPLE
        Connect-PS TAS-ISD-SYS10

        .FORWARDHELPCATEGORY Alias
        remote
    #>

    Param(
        # Computer to ps remote into
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Computer
    )
    $IAAccount = "$Env:USERDOMAIN\$Env:USERNAME-IA"

    $OS = Get-ADComputer $Computer -Properties OperatingSystem | Select-Object -ExpandProperty OperatingSystem
    if ($OS -like '*Server*') {
        Enter-PSSession -ComputerName $Computer -Credential $IAAccount
    } else {
        Enter-PSSession -ComputerName $Computer
    }
}

function Search-Computer {
    <#
        .Description
        Searches for AD computers using the computer name by default. Can be switched to search descriptions. Search includes servers only but can be switched to include
        workstations as well.

        .EXAMPLE
        Search-Computer -d HVAC

        .FORWARDHELPCATEGORY Alias
        sm
    #>

    Param(
        # Computer to search.
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        [string]
        $Computer,

        # Switch to search for workstations. Otherwise command will only return servers.
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
        [switch]
        $Workstation,

        # Switch to include description in the search
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
        [switch]
        $Description
    )
    if ($Description -eq $True) {
        $Filter = "Name -like '*$Computer*' -or SamAccountName -like '*$Computer*' -or Description -like '*$Computer*'"
    } else {
        $Filter = "Name -like '*$Computer*' -or SamAccountName -like '*$Computer*'"
    }
    if ($Workstation -eq $True) {
        $Filter += " -and OperatingSystem -notlike '*Server*'"
    } else {
        $Filter += " -and OperatingSystem -like '*Server*'"
    }

    $Computers = Get-ADComputer -Filter $Filter -Properties *

    $DefaultDisplaySet = 'Name', 'SamAccountName', 'Description', 'Location'
    $Computers = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $Computers

    return $Computers
}

function Copy-ItemOverPS {
    <#
        .Description
        Copies files over a PS Remote session

        .EXAMPLE
        Copy-ItemOverPS -Computer DC-PRD-JAVTOOL -Source 'computerlist.csv' -Destination 'C:\Users\LukeD-IA\computerlist.csv'

        .FORWARDHELPCATEGORY Alias
        pscp
    #>
    Param(
        # Computer to copy the file to.
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        [string]
        $Computer,

        # Item to copy
        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$false)]
        [string]
        $Source,

        # Destination
        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$false)]
        [string]
        $Destination
    )
    $Session = New-PSSession -ComputerName "$Computer" -Credential "$env:USERDOMAIN\$env:USERNAME-IA" -Name "TMP-PSCP-SESSION"
    Copy-Item "$Source" -Destination "$Destination" -ToSession $Session -Recurse
    Remove-PSSession -Name "TMP-PSCP-SESSION"
}

function Get-Sessions {
    <#
        .Description
        Gets sessions on a target computer via qwinsta

        .EXAMPLE
        Get-Sessions TAS-ISD-SYS10

        .FORWARDHELPCATEGORY Alias
        w
    #>

    Param(
        # Computer to check with qwinsta
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [string]
        $ComputerName = $Env:COMPUTERNAME
    )
    qwinsta /server:$ComputerName
}

function Get-UserTeam {
    <#
        .Description
        Gets other users that share the same Manager attribute.

        .EXAMPLE
        Get-UserTeam luked

        .FORWARDHELPCATEGORY Alias
        team
    #>

    Param(
        # User to get the team members of
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity=$env:USERNAME
    )

    $Manager = Get-ADUser -Identity $Identity -Properties Manager | Select-Object -ExpandProperty Manager
    $TeamMembers = Get-ADUser -Filter "Manager -eq '$Manager'" -Properties *

    $DefaultDisplaySet = 'DisplayName', 'Name', 'Title', 'Office', 'Telephone', 'Mail'
    $TeamMembers = Set-DefaultDisplaySet -DefaultDisplaySet $defaultDisplaySet -Object $TeamMembers

    return $TeamMembers
}

function mtree {
    Param(
        # Base user
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [string]
        $Identity=$env:USERNAME
    )
    $ManagerChain = @()
    #New-Object System.Collections.Generic.List[string]
    $User = Get-ADUser -Identity $Identity -Properties DisplayName, Manager

    for (;$User.Manager -notlike $User;) {
        $UserManager = Get-ADuser -Identity $User.Manager -Properties DisplayName, Manager
        $ManagerChain += $UserManager # Add user's manager to list
        # Get-ADUser for the manager and set that as the new user to check.
        $User = Get-ADUser -Identity $User.Manager -Properties DisplayName, Manager
    }

    # Get a count of the list then use that to loop over the list in reverse.
    for ($index=$ManagerChain.Count; $index -ge 0; $index--) {
        $ManagerName = ($ManagerChain[$index]).DisplayName
        for ($i=0; $i -le $ChainLength; $i++) {
            $ManagerName = $ManagerName.Insert($i, ' ')
        }
        $ManagerName = $ManagerName.Insert($ChainLength, '\')
        Write-Output $ManagerName
    }
}

function Open-MFPWebInterface {
    Param(
        # Printer to get the IP of
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        $Printer
    )
    $IPAddress = Get-ADPrinter $Printer | Select-Object -First 1 -ExpandProperty PortName
    Start-Process http://$IPAddress
}

function Get-Site {
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$true)]
        [string]
        $Search,

        # search
        [Parameter(Mandatory=$False)]
        [ValidateSet("Loc #","Site & Stop #","Site Code","Old Site Abbv","HCP #","Facility Name","Address - Full","City","State","Business Hours","MDF (Name/RM#)",`
        "IDF (Name/RM#)","Demarc (Name/RM#)","YVFWC Owned Facility?","Notes","Spectrum WAN Circuit ID","Lumen WAN Circuit ID")]
        [string]
        $SearchField="Site Code"
    )
    $InvFile = "$Env:Temp\YVFWC Site Facilities Inventory.csv"

    if (-not(Test-Path -Path $InvFile -PathType Leaf)) {
        Write-Error "No invetory file found. Please copy inventory to $InvFile"
    } else {
        $InvData = Import-Csv $InvFile
        $SearchResults = $InvData | Where-Object $SearchField -like "*$Search*"
    }
    Write-Output $SearchResults
}

Set-Alias -Name user -Value Get-User
Set-Alias -Name groups -Value Get-UserGroups
Set-Alias -Name groupdiff -Value Compare-UserGroups
Set-Alias -Name aadgroups -Value Get-UserAADGroups
Set-Alias -Name name -Value Get-UserName
Set-Alias -Name pw -Value Get-UserPWInfo
Set-Alias -Name site -Value Get-Site
Set-Alias -Name remote -Value Connect-PS
Set-Alias -Name sm -Value Search-Computer
Set-Alias -Name pscp -Value Copy-ItemOverPS
Set-Alias -Name w -Value Get-Sessions
Set-Alias -Name team -Value Get-UserTeam

Export-ModuleMember -Alias * -Function `
  Get-User`
  Get-UserGroups`
  Compare-UserGroups`
  Get-UserName`
  Get-UserPWInfo`
  Connect-PS`
  Search-Computer`
  Copy-ItemOverPS`
  Get-Sessions`
  Get-UserTeam`
  Open-MFPWebInterface`
  Get-Site`
