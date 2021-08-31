#############################################################################
############# Checker les vulnérabiltés des postes de travail : #############
######################## Auteur : Pierre-Alban MAURIN #######################
##### Prérequis 1 : Droits admin locaux (conseillé) #########################
##### Prérequis 2 : nmap (conseillé)     ####################################
#############################################################################

####################################
## Initialisation des variables : ##
####################################
Import-Module ActiveDirectory
$domaine = Get-ADDomain | select forest | Format-Wide
$user = whoami.exe
mkdir C:\AuditPoste
$ErrorActionPreference= 'silentlycontinue'

################
## Fonctions  ##
################

function Get-DomaineCoucouGUI {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $ForestArguments = @{}
    if ($PSBoundParameters['Credential']) { $ForestArguments['Credential'] = $Credential }

    try {
        $SchemaPath = (Get-Forest @ForestArguments).schema.name
    }
    catch {
        throw '[Get-DomaineCoucouGUI] Error in retrieving forest schema path from Get-Forest'
    }
    if (-not $SchemaPath) {
        throw '[Get-DomaineCoucouGUI] Error in retrieving forest schema path from Get-Forest'
    }

    $SearcherArguments = @{
        'SearchBase' = $SchemaPath
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
    if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
    if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
    if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    $SchemaSearcher = Get-DomainSearcher @SearcherArguments

    if ($SchemaSearcher) {
        try {
            $Results = $SchemaSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomaineCoucouGUI] Error disposing of the Results object: $_"
                }
            }
            $SchemaSearcher.dispose()
        }
        catch {
            Write-Verbose "[Get-DomaineCoucouGUI] Error in building GUID map: $_"
        }
    }

    $SearcherArguments['SearchBase'] = $SchemaPath.replace('Schema','Extended-Rights')
    $SearcherArguments['LDAPFilter'] = '(objectClass=controlAccessRight)'
    $RightsSearcher = Get-DomainSearcher @SearcherArguments

    if ($RightsSearcher) {
        try {
            $Results = $RightsSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomaineCoucouGUI] Error disposing of the Results object: $_"
                }
            }
            $RightsSearcher.dispose()
        }
        catch {
            Write-Verbose "[Get-DomaineCoucouGUI] Error in building GUID map: $_"
        }
    }

    $GUIDs
}
function Get-DomaineCoucou {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            write-verbose "get-domain"
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters['Server']) {
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomaineCoucou] search base: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomaineCoucou] Using alternate credentials for LDAP connection"
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}
function Find-Process {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('chocolatine.coucou.Process')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),

        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    BEGIN {
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name


        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }

    PROCESS {

        ForEach ($ProcessName in $Name) {

            $TargetProcess = Get-Process -Name $ProcessName

            if ($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($Null -ne $TargetProcess.Path)) {

                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent
                    $LoadedModules = $TargetProcess.Modules
                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]

                    ForEach ($Module in $LoadedModules){

                        $ModulePath = "$BasePath\$($Module.ModuleName)"

                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {

                            $Exclude = $False

                            if ($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }

                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'Processcoucou' $ModulePath
                                $Out.PSObject.TypeNames.Insert(0, 'chocolatine.coucou.Process')
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}
function Find-Path {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('chocolatine.coucou.Path')]
    [CmdletBinding()]
    Param()

    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_
        $ModifidablePaths = $TargetPath | Get-ModifiablePath -Literal | Where-Object {$_ -and ($Null -ne $_) -and ($Null -ne $_.ModifiablePath) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach ($ModifidablePath in $ModifidablePaths) {
            if ($Null -ne $ModifidablePath.ModifiablePath) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath | Add-Member Aliasproperty Name '%PATH%'
                $ModifidablePath.PSObject.TypeNames.Insert(0, 'chocolatine.coucou.Path')
                $ModifidablePath
            }
        }
    }
}
function Get-chocoACL {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $DistinguishedName = "*",

        [Switch]
        $ResolveGUIDs,

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $RightsFilter,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomaineCoucou -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize -Domain $Domaine

        if($ResolveGUIDs) {
            $GUIDs = Get-DomaineCoucouGUI -DomainController $DomainController -PageSize $PageSize -Domain $Domain
        }
    }

    process {

        if ($Searcher) {

            if($SamAccountName) {
                $Searcher.filter="(&(samaccountname=$SamAccountName)(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
            else {
                $Searcher.filter="(&(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
  
            try {
                $Searcher.FindAll() | Where-Object {$_} | Foreach-Object {
                    $Object = [adsi]($_.path)
                    if($Object.distinguishedname) {
                        $Access = $Object.PsBase.ObjectSecurity.access
                        $Access | ForEach-Object {
                            $_ | Add-Member NoteProperty 'ObjectDN' ($Object.distinguishedname[0])

                            if($Object.objectsid[0]){
                                $S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                            }
                            else {
                                $S = $Null
                            }
                            
                            $_ | Add-Member NoteProperty 'ObjectSID' $S
                            $_
                        }
                    }
                } | ForEach-Object {
                    if($RightsFilter) {
                        $GuidFilter = Switch ($RightsFilter) {
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            Default { "00000000-0000-0000-0000-000000000000"}
                        }
                        if($_.ObjectType -eq $GuidFilter) { $_ }
                    }
                    else {
                        $_
                    }
                } | Foreach-Object {
                    if($GUIDs) {
                        $AclProperties = @{}
                        $_.psobject.properties | ForEach-Object {
                            if( ($_.Name -eq 'ObjectType') -or ($_.Name -eq 'InheritedObjectType') ) {
                                try {
                                    $AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $AclProperties[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $AclProperties[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $AclProperties
                    }
                    else { $_ }
                }
            }
            catch {
                Write-Warning $_
            }
        }
    }
}

#############################################
## Recherches des mots de passe en clair : ##
#############################################
# Fichiers
Write-Host "[o] Recherches de mots de passe en clair - Fichiers :"`r 
$pathuser = $env:HOMEPATH
cd $pathuser
$mdptxt = 'Mot de passe'
cd .\Desktop
$mdp = findstr.exe /si password *.xml *.ini *.txt *.config `r 
$mdp
$mdp1 = findstr.exe /si $mdptxt *.xml *.ini *.txt *.config `r 
$mdp1
cd ..\Documents
$mdp2 = findstr.exe /si password *.xml *.ini *.txt *.config `r 
$mdp2
$mdp3 = findstr.exe /si $mdptxt *.xml *.ini *.txt *.config `r 
$mdp3
cd ..\Downloads
$mdp4 = findstr.exe /si password *.xml *.ini *.txt *.config `r 
$mdp4
$mdp5 = findstr.exe /si $mdptxt *.xml *.ini *.txt *.config `r 
$mdp5
cd C:\AuditPoste

$MdpFichiers = $mdp + "`r" + $mdp1 + "`r" + $mdp2 + "`r" + $mdp3 + "`r" + $mdp4 + "`r" + $mdp5


# Clés de registre
Write-Host "[o] Recherches de mots de passe en clair - Clés de registres :"
$CleDeRegistre = reg query HKLM /F password /t REG_SZ /S > cle.txt

## Tri desclés de registres
Get-Content .\cle.txt | Where-Object {$_ -notmatch '(by default)'} | Set-Content out.txt
Get-Content .\out.txt | Where-Object {$_ -notmatch '(par défaut)'} | Set-Content out1.txt
Get-Content .\out1.txt | Where-Object {$_ -notmatch 'parentPolicyMajor'} | Set-Content out2.txt
Get-Content .\out2.txt | Where-Object {$_ -notmatch 'parentPolicyMinor'} | Set-Content out3.txt
Get-Content .\out3.txt | Where-Object {$_ -notmatch 'ActivatableClassId'} | Set-Content out4.txt
Get-Content .\out4.txt | Where-Object {$_ -notmatch 'FilterIn'} | Set-Content out5.txt
Get-Content .\out5.txt | Where-Object {$_ -notmatch 'RelativePath'} | Set-Content out6.txt
Get-Content .\out6.txt | Where-Object {$_ -notmatch 'InfoTip'} | Set-Content out7.txt
Get-Content .\out7.txt | Where-Object {$_ -notmatch 'ADDS-Kerberos-Password-UDP-In'} | Set-Content out8.txt
Get-Content .\out8.txt | Where-Object {$_ -notmatch 'ADDS-Kerberos-Password-TCP-In'} | Set-Content out9.txt
Get-Content .\out9.txt | Where-Object {$_ -notmatch 'devicename'} | Set-Content out10.txt
Get-Content .\out10.txt | Where-Object {$_ -notmatch 'Picture Password Enrollment UX'} | Set-Content out11.txt
Get-Content .\out11.txt | Where-Object {$_ -notmatch 'PicturePasswordLogonProvider'} | Set-Content out12.txt
Get-Content .\out12.txt | Where-Object {$_ -notmatch 'http://schemas.microsoft.com'} | Set-Content out13.txt
Get-Content .\out13.txt | Where-Object {$_ -notmatch 'Microsoft Clear Text Password Security Provider'} | Set-Content out14.txt
Get-Content .\out14.txt | Where-Object {$_ -notmatch 'HKEY_LOCAL_MACHINE'} | Set-Content out15.txt
Get-Content .\out15.txt | Where-Object {$_ -notmatch 'HKEY_CURRENT_USER'} | Set-Content out16.txt
Get-Content .\out16.txt | Where-Object {$_ -notmatch 'Prompt for user name and password'} | Set-Content out17.txt
Get-Content .\out17.txt | Where-Object {$_ -notmatch 'Automatic logon with current user name and password'} | Set-Content out18.txt
Get-Content .\out18.txt | Where-Object {$_ -notmatch 'Fin de la recherche'} | Set-Content out19.txt
Get-Content .\out19.txt | Where-Object {$_ -ne ''} | Set-Content out20.txt

$CleDeRegistre = Get-Content .\out20.txt
$CleDeRegistre


#Dump des clés Wifi
Write-Host "[o] Recherches de mots de passe en clair - Wifi :"
$wifi1 = netsh wlan show profiles |Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} 
$wifi1 | %{(netsh wlan show profile name="$name" key=clear)} | Select-String "Contenu de la clé\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} 
$wifi1 | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Wide > .\Wifi-temp.txt
Type .\Wifi-temp.txt | Select -Unique > .\Wifi.txt
rm .\Wifi-temp.txt

$CleWifi = Get-Content .\Wifi.txt | select -Skip 3
$CleWifi = $CleWifi -replace 'wlan show profiles.',''
rm .\Wifi.txt
if ($CleWifi)
    {
        Write-Host "Attention, les clés wifi suivantes sont en clair :" -BackgroundColor Red
        $CleWifi
    }
Else
    {
        Write-Host "Il n'y a a priori pas de clés wifi en clair." -BackgroundColor DarkGreen
        $CleWifi = "Il n'y a a priori pas de cles wifi en clair."
    }

#############################################
####### Recherches des DLL Hijacking : ######
#############################################
# Process vulnérables
Write-Host "[o] Recherches des DLLHijacking"
$hijck = Get-Process | Find-Process -ExcludeWindows -ErrorAction silentlycontinue
$hijck


#############################################
## Recherches des Unquoted services Path : ##
#############################################
# Chemins vulnérables
Write-Host "[o] Recherches de vuln Unquoted Services Path"
$chocolatineservice = gwmi win32_service | ?{$_} | where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | where {-not $_.pathname.StartsWith("`"")} | where {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -match ".* .*"}
    
if ($chocolatineservice) {
    foreach ($service in $chocolatineservice){
        $out = New-Object System.Collections.Specialized.OrderedDictionary
        $out.add('ServiceName', $service.name)
        $out.add('Path', $service.pathname)
        $out 
        $UnquotedPath = $out   
    }
}
Else
    {
        Write-Host "Le système n'a a priori pas de Unquoted Services Path." -BackgroundColor DarkGreen
        $UnquotedPath = "Le système n'a a priori pas de Unquoted Services Path."
    }



#######################################################
## Recherches des fichiers install sans assistance : ##
#######################################################
# Fichiers
Write-Host "[o] Recherches des fichiers d'installation sans assistance"
cd C:\Windows\Panther\
$install = findstr.exe /si password unattend.xml sysprep.xml sysprep.inf
cd C:\Windows\System32
$install1 = findstr.exe /si password unattend.xm sysprep.xml sysprep.inf
cd C:\AuditPoste

$unattendXML = $install + $install1
$unattendXML

###############################################
## Recherches de AlwaysInstallatedElevated : ##
###############################################
# Vérification de la clé de registre
Write-Host "[o] Recherches de vuln AlwaysInstallatedElevated"
$AlwaysInstallValeur = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated
if ($AlwaysInstallValeur)
    {
        Write-Host "Attention, AlwaysInstallElevated est à 1 !" -BackgroundColor Red
        $AlwaysInstall = "Attention, AlwaysInstallElevated est a 1 !"
    }
Else
    {
        Write-Host "Le système n'est pas vulnérable à AlwaysInstallElevated." -BackgroundColor DarkGreen
        $AlwaysInstall = "Le système n'est pas vulnérable a AlwaysInstallElevated."
    }

###################################
## Recherches de mauvaises ACL : ##
###################################
# Check
Write-Host "[o] Recherches des mauvaises ACL"
$MauvaisesACL = Get-chocoACL -ResolveGUIDs | ? {$_.IdentityReference -eq $user} | select ObjectDN,ActiveDirectoryRights,AccessControlType
if ($MauvaisesACL)
    {
    Write-Host "Les ACL a surveiller sont les suivantes" -BackgroundColor Red
    $MauvaisesACL
    }
else
    {
    Write-Host "Il n'ya pas à priori d'ACL vulnérables." -BackgroundColor DarkGreen
    $MauvaisesACL = "Il n'ya pas a priori d'ACL vulnerables."
    }



##########################
## Recherches des CVE : ##
##########################
# Check nmap
Write-Host "[o] Recherches de vuln CVE"
$NmapExiste = Test-Path 'C:\Program Files (x86)\Nmap'
if ($NmapExiste)
    {
    nmap --script=vuln 127.0.0.1 > nmap.txt
    $nmap = Get-Content .\nmap.txt
    $nm = $nmap | findstr.exe 'CVE'
    $nm1 = $nmap | findstr.exe 'smb-vuln'
    $CVENmap = $nm + $nm1
    $CVENmap
    }
else
    {
    Write-Host "Impossible de scanner le poste en l'absence de Nmap." -BackgroundColor Red
    $CVENmap = "Impossible de scanner le poste en l'absence de Nmap."
    }


#########################################
## Recherches de vuln Printnightmare : ##
#########################################
# Vérification de la clé de registre
Write-Host "[o] Recherches de vuln Printnightmare"
$PrintNightmareValue = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name NoWarningNoElevationOnInstall -ErrorAction SilentlyContinue
if ($PrintNightmareValue)
    {
        Write-Host "Attention, Le système est vulnérable à PrintNightmare !" -BackgroundColor Red
        $PrintNightmare = "Attention, Le systeme est vulnerable a PrintNightmare !"
    }
Else
    {
        Write-Host "Le système n'est pas vulnérable à PrintNightmare." -BackgroundColor DarkGreen
        $PrintNightmare = "Le systeme n'est pas vulnerable a PrintNightmare."
    }

##########################
## Disque dur chiffré : ##
##########################
# Vérification de la clé de registre
Write-Host "[o] Vérification du disque dur"
$DDchiffreValue = Get-BitLockerVolume -MountPoint C: | select ProtectionStatus |Format-Wide
if ($DDchiffreValue -eq 'on')
    {
        Write-Host "Le disque dur est bien chiffré." -BackgroundColor DarkGreen
        $DDchiffre = "Le disque dur est bien chiffre."
    }
Else
    {
        Write-Host "Attention, le disque dur n'est pas chiffré !" -BackgroundColor Red
        $DDchiffre = "Attention, le disque dur n'est pas chiffre !"
    }


###########################################
## Vérification des tâches plannifiées : ##
###########################################
# check TP :
Write-Host "[o] Vérification des tâches plannifiées"
$TachePlannifiees = schtasks.exe /query /fo CSV /v |ConvertFrom-Csv |where "Exécuter en tant qu'utilisateur" -NotLike "Exécuter en tant qu'utilisateur" | where Statut -notlike Désactivée |where "Nom de la tâche" -NotLike "\Microsoft*" | select "Nom de la tâche","Type de planification","Tâche à exécuter","Exécuter en tant qu'utilisateur"
if ($TachePlannifiees)
    {
        Write-Host "Attention, veuillez vérifier les tâches suivantes :`r" -BackgroundColor Red
        $TachePlannifiees
    }
Else
    {
        Write-Host "Il n'y a a priori pas de tâches plannifiées suspectes." -BackgroundColor DarkGreen
        $TachePlannifiees = "Il n'y a a priori pas de taches plannifiees suspectes."
    }


##############################
## Utilsiation de WDigest : ##
##############################
# Vérification de la clé de registre
Write-Host "[o] Recherches d'une utilisation de WDigest"
$wdigest = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -Name UseLogonCredential
if ($wdigest)
    {
        Write-Host "Attention, le provider Wdigest est utilisé !" -BackgroundColor Red
        $UtilisationWdigest = "Attention, le provider Wdigest est utilise !"
    }
Else
    {
        Write-Host "le provider Wdigest n'est pas utilisé." -BackgroundColor DarkGreen
        $UtilisationWdigest = "le provider Wdigest n'est pas utilise."
    }


########################
## vuln GPPPassword : ##
########################
# Vérification au niveau du sysvol
Write-Host "[o] Recherches de la vulnérabilité GPPPassword"
$gpppassword = findstr.exe /S /I cpassword \\$domaine\sysvol\$domaine\policies\*.xml
if ($gpppassword)
    {
        Write-Host "Attention, le domaine est vulnérable au GPPPassword !" -BackgroundColor Red
        $UtilsationGPPPassword = "Attention, le domaine est vulnerable au GPPPassword !"
    }
Else
    {
        Write-Host "Le domaine n'est pas vulnérable au GPPPassword." -BackgroundColor DarkGreen
        $UtilsationGPPPassword = "Le domaine n'est pas vulnerable au GPPPassword."
    }


################################################################
########################## Partie 2 : ##########################
################################################################
###################### Exportation en CSV ######################
##>

cd C:\AuditPoste

$results = @()
$RenduFinal = @{
        MdpClairFichiers       = $MdpFichiers
        MdpClairCles           = [string]$CleDeRegistre
        MdpClairWifi           = [string]$CleWifi
        DLLHijacking           = $hijck | Out-String 
        UnquotedServicesPath   = $UnquotedPath | Out-String            
        UnattendXLM            = [string]$unattendXML                 
        AllwaysInstallElevated = $AlwaysInstall 
        MauvaisesACL           = $MauvaisesACL
        CVENmap                = $CVENmap
        PrintNightmare         = $PrintNightmare
        DDchiffre              = $DDchiffre
        TachePlannifiees       = $TachePlannifiees | Out-String
        UtilisationWdigest     = $UtilisationWdigest
        UtilsationGPPPassword  = $UtilsationGPPPassword
} 

$results += New-Object PSObject -Property $RenduFinal  
$results | export-csv -Path C:\AuditPoste\Rendu.csv -NoTypeInformation

################ Exportation du rapport en HTML ################
Write-Host "Exportation du rapport en HTML" -BackgroundColor Blue


$header=@"
<head>
<title>Rapport audit du poste</title>
</head><body>
<table>
<colgroup><col/><col/><col/><col/></colgroup>
<tr><th>Vulnérabilité</th><th>Commentaire(s)</th></tr>
<style>
h1, h5, th { text-align: center; font-family: Segoe UI; }
table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
th { background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; }
td { font-size: 11px; padding: 5px 20px; color: #000; }
tr { background: #b8d1f3; }
tr:nth-child(even) { background: #dae5f4; }
tr:nth-child(odd) { background: #b8d1f3; }
</style>
"@
$footer=@"
</table>
</body></html>
"@
$body=@"
<h1>Rapport audit du poste $(hostname)</h1>
<h5>Domaine : $($env:userdnsdomain) </h5>
<h5>Généré le $(Get-Date)
"@

Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Mdp en clair dans des Fichiers</td><td>$($_.MdpClairFichiers)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Mdp en clair dans des clés de registres</td><td>$($_.MdpClairCles)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Mdp en clair dans des clés WiFi</td><td>$($_.MdpClairWifi)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Potentielles DLL Hijacking</td><td>$($_.DLLHijacking)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Potentiels Unquoted Services Path</td><td>$($_.UnquotedServicesPath)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Fichiers d'installation sans assistance</td><td>$($_.UnattendXLM)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Présence de Allways Install Elevated</td><td>$($_.AllwaysInstallElevated)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>ACL à surveiller</td><td>$($_.MauvaisesACL)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Potentielles CVE</td><td>$($_.CVENmap)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Vulnérabilité PrintNightmare</td><td>$($_.PrintNightmare)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Disque dur chiffré</td><td>$($_.DDchiffre)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Tâches plannifiées à surveiller</td><td>$($_.TachePlannifiees)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>Utilisation de WDigest</td><td>$($_.UtilisationWdigest)</td></tr>"
}
Import-Csv C:\AuditPoste\Rendu.csv | ForEach{
    $body+="<tr><td>UtilsationGPPPassword</td><td>$($_.UtilsationGPPPassword)</td></tr>"
}
-join $header,$body,$footer | Out-File .\RapportAudit.html

Write-Host "[o] Votre rapport final se trouve sur votre bureau : RapportAudit.html" -BackgroundColor Black
$pathuser = $env:HOMEPATH
cd $pathuser
cd .\Desktop

cp C:\AuditPoste\RapportAudit.html .\

Invoke-Expression .\RapportAudit.html
rm -r C:\AuditPoste
Write-Host "Fin" -BackgroundColor Blue
###### FIN ###### 