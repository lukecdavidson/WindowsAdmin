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

    Write-Output $User | Select-Object `
        DisplayName,`
        Title,`
        Department,`
        @{N='Site';E={$_.physicalDeliveryOfficeName}},`
        @{N='Manager';E={((($_.Manager -split 'CN=')[1]) -split ',')[0]}},`
        @{N='Subordinates';E={$Subordinates}},`
        @{N='Phone';E={$_.telephoneNumber}},`
        @{N='Email';E={$_.mail}},`
        @{N='Created';E={$_.whenCreated}},`
        @{N='Organization Unit';E={($_.DistinguishedName -split ',',2)[1]}}
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

    $User = Get-ADUser -Identity $Identity -Properties memberOf | Select-Object memberOf
    switch ($Output) {
        short { $User | Select-Object -ExpandProperty memberOf | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object }
        long { $User | Select-Object -ExpandProperty memberOf | Sort-Object }
        object { $User }
        Default { $User | Select-Object -ExpandProperty memberOf | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object }
    }
}

function Compare-UserGroups {
    <#
        .Description
        Compares group membership between two AD users.

        .EXAMPLE
        Compare-UserGroups luked luiso

        .EXAMPLE
        Compare-UserGroups luked luiso -DiffType luked -Output long

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
        $Identity2,

        # Output diff type
        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
        [string]
        $DiffType,

        # Output as object
        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [string]
        $Output
    )

    $User1 = Get-ADUser -Identity $Identity1 -Properties memberOf | Select-Object -ExpandProperty memberOf
    $User2 = Get-ADUser -Identity $Identity2 -Properties memberOf | Select-Object -ExpandProperty memberOf
    $Diff = Compare-Object $User1 $User2

    switch ($DiffType) {
        $User1 { $Diff = $Diff | Where-Object SideIndicator -eq '<=' }
        $User2 { $Diff = $Diff | Where-Object SideIndicator -eq '=>' }
        Diff { }
        Default { }
    }
    switch ($Output) {
        short { $Diff | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object }
        long { $Diff | Sort-Object }
        Default { $Diff | ForEach-Object{((($_ -split 'CN=')[1]) -split ',')[0]} | Sort-Object }
    }
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
        $Identity,

        # Output as object
        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false)]
        [string]
        $Output
    )
    $Users = Get-ADUser -Filter "DisplayName -like '*$Identity*'"
    switch ($Output) {
        short { $Users | Select-Object -ExpandProperty Name }
        long { foreach ($User in $Users) { user -Identity $User } }
        object { $Users }
        Default { $Users | Select-Object -ExpandProperty Name }
    }
    
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
        $Identity,

        # Action to take: view user or reset password. Defaults to view
        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false)]
        [string]
        $Action="view"
    )
    $User = Get-ADUser -Identity $Identity -Properties * | Select-Object `
        DisplayName,`
        Name,`
        Enabled,`
        LockedOut,`
        PasswordExpired,`
        PasswordLastSet,`
        LastBadPasswordAttempt,`
        LastLogonDate,`
        Modified,`
        DistinguishedName
    switch ($Action) {
        view { Write-Output $User }
        unlock { Unlock-ADAccount -Identity $Identity}
        Default { Write-Output $User }
    }
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
        $Description,

        # Format of output
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
        [string]
        $Output
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

    switch ($Output) {
        short { $Computers | Select-Object -ExpandProperty Name }
        long { $Computers | Select-Object Name, SamAccountName, Description, Location }
        object { $Computers }
        Default { $Computers | Select-Object Name, Description, Location }
    }
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
        $Identity=$env:USERNAME,

        # Format of output
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
        [string]
        $Output
    ) 
    $Manager = Get-ADUser -Identity $Identity -Properties Manager | Select-Object -ExpandProperty Manager
    $TeamMembers = Get-ADUser -Filter "Manager -eq '$Manager'" -Properties *
    switch ($Output) {
        short { $TeamMembers | Select-Object -ExpandProperty DisplayName }
        long { $TeamMembers | Select-Object Name }
        object { $TeamMembers }
        Default { $TeamMembers | Select-Object -ExpandProperty DisplayName }
    }
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

Export-ModuleMember -Function * -Alias *