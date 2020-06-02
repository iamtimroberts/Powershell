Function AdminPS {
    Start-process powershell -verb runas
}
Function Get-LoggedOnUser {
    Param(
        [CmdletBinding()]
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$ComputerName
    )
    $oldverbose = $VerbosePreference
    $VerbosePreference = "continue"
    try {
        Test-Connection $ComputerName -count 1 -quiet -ErrorAction Stop | out-null
        Get-WmiObject win32_computersystem -ComputerName $ComputerName -ErrorAction Stop | Select Username, Name
    }
    catch {
        Write-Host "$ComputerName is unavailable." -Verbose -ForegroundColor DarkCyan
    }
    $VerbosePreference = $oldverbose
}
Function Search-GPOString {
    Param( [Array]$SearchString )
    $DomainName = $env:USERDNSDOMAIN
    Import-Module GroupPolicy
    $allGposInDomain = Get-GPO -All -Domain $DomainName
    Write-Host "Starting search for $SearchString ...."
    foreach ($gpo in $allGposInDomain) {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        $termFound = @()
        foreach ($term in $SearchString) {
            if ($report -match $term) {
                $termFound += $term
            }
        }
        if ($termFound) {
            Write-Host -ForegroundColor Cyan "$($gpo.DisplayName) [$($termFound -join ",")]"
        }
    }
}
Function Search-GPO {
    Param( [String]$SearchString )
    $DomainName = $env:USERDNSDOMAIN
    Import-Module GroupPolicy
    $Match = Get-GPO -All -Domain $DomainName | ? { $_.DisplayName -like "*$SearchString*" }
    If ($null -eq $Match) {
        Write-Host 'No matching GPOs were found.'
    }
    Else {
        $Match
    }
}
Function Search-ADUser {
    Param( [String]$SearchString )
    $Match = Get-ADUser -Filter { anr -like $SearchString } -Properties Mail
    If ($null -eq $Match) {
        # Nothing was found
        Write-Host 'No matching accounts were found.'
    }
    Else {
        $Match
    }
}
Function Search-ADGroup {
    Param( [String]$SearchString )
    $Match = get-adgroup -Filter "Name -like '*$($SearchString)*' -or Description -like '*$($SearchString)*'" -Properties Description
    If ($null -eq $Match) {
        # Nothing was found
        Write-Host 'No matching groups were found.'
    }
    Else {
        $Match
    }
}
Function Search-ADEmail {
    Param( [String]$SearchString )
    $Match = Get-ADObject -Properties mail, proxyAddresses, SamAccountName -Filter { mail -like $SearchString -or proxyAddresses -like $SearchString } |
    Select-Object DistinguishedName, Name, SAMAccountName, Enabled, Mail, @{"name" = "ProxyAddresses"; "expression" = { $_.proxyaddresses -join "`r`n" | out-string } }          
    If ($null -eq $Match) {
        # Nothing was found
        Write-Host 'No matching email addresses were found.'
    }
    Else {
        $Match
    }
}
Function Get-ADUserDetails {
    [cmdletbinding()]
    Param(
        [parameter(ValueFromPipeline)]$SearchString
    )
    $Props = @('Name', 'Description', 'Title', 'Department', 'DistinguishedName', 'accountExpires', 'BadLogonCount', 'EmailAddress', 'Enabled', 'LastBadPasswordAttempt',
        'LastLogonDate', 'LockedOut', 'Manager', 'PasswordLastSet', 'SamAccountName', 'UserPrincipalName', 'whenChanged', 'whenCreated')
    $Match = Get-ADUser -Identity $SearchString -Properties $Props | Select-Object -Property $props
    If ($null -eq $Match) {
        # Nothing was found
        Write-Host 'No matching accounts were found.'
    }
    Else {
        $Groups = Get-ADPrincipalGroupMembership $SearchString | Sort-Object -Property Name | Select-object -ExpandProperty name
        $Match | Add-Member -MemberType NoteProperty -Name Groups -Value ($Groups -join "`r`n" | out-string)
        $Match
    }
}
Function Search-ADComputer {
    Param(
        [String]$SearchString
    )
    $Match = Get-ADComputer -Filter "Name -like '*$($SearchString)*' -or Description -like '*$($SearchString)*'" -Properties Description
    If ($null -eq $Match) {
        # Nothing was found
        Write-Host 'No matching computers were found.'
    }
    Else {
        $Match
    }
}
Function Get-ADComputerDetails {
    [cmdletbinding()]
    Param(
        [String]$SearchString
    )
    $Props = @('Name', 'Description', 'BadLogonCount', 'DistinguishedName', 'DNSHostName', 'Enabled', 'IPv4Address', 'LastBadPasswordAttempt', 'LastLogonDate', 'ManagedBy', 'OperatingSystem', 'whenCreated')
    $Match = Get-ADComputer -Identity $SearchString -Properties $Props
    If ($null -eq $Match) {
        # Nothing was found
        Write-Host 'No matching accounts were found.'
    }
    Else {
        $Match | Select-Object -Property $props
    }
}
Function Set-ScriptSignature {
    Param(
        [String]$NewScript
    )
    $cert = (Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert)
    Set-AuthenticodeSignature -TimestampServer "http://timestamp.globalsign.com/scripts/timstamp.dll" -FilePath $NewScript -Certificate $cert
}
Function Get-UserGroups {
    Param(
        [CmdletBinding()]
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [String]$SamAccountName
    )
    Get-ADPrincipalGroupMembership $SamAccountName | Select-Object Name | Sort-Object -Property Name
}