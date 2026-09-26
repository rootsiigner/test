<#
.SYNOPSIS
    Trouve et supprime les references Windows qui pointent vers un dossier
    supprime (ex : C:\Users\medzo.DESKTOP-NADQE19), responsables du message
    "Emplacement non disponible".

.DESCRIPTION
    Analyse les endroits ou Windows garde un chemin en dur :
      - dossiers speciaux de l'utilisateur (Bureau, Documents, Images...)
      - programmes lances au demarrage (registre Run + dossier Demarrage)
      - raccourcis du Bureau et du menu Demarrer
      - taches planifiees
      - variables d'environnement de l'utilisateur

    Par defaut le script est en LECTURE SEULE : il liste ce qu'il a trouve
    sans rien modifier. Ajoute -Fix pour appliquer les corrections, apres
    sauvegarde automatique.

    N'a PAS besoin de droits administrateur (ne touche qu'au profil courant).

.EXAMPLE
    .\Fix-DeadProfilePath.ps1
    Analyse seule. Affiche toutes les references cassees trouvees.

.EXAMPLE
    .\Fix-DeadProfilePath.ps1 -Fix
    Applique les corrections (sauvegarde faite avant toute modification).

.EXAMPLE
    .\Fix-DeadProfilePath.ps1 -Fix -IncludeQuickAccess
    Corrige, et reinitialise aussi l'Acces rapide de l'Explorateur.

.NOTES
    Ce script ne touche JAMAIS a HKLM\...\ProfileList : modifier cette cle
    peut empecher l'ouverture de session. Il ne corrige que les pointeurs.
#>
[CmdletBinding()]
param(
    # Restreint l'analyse a un chemin precis. Par defaut, toute reference
    # vers un dossier inexistant est signalee.
    [string]$BadPath,

    # Sans ce commutateur, le script se contente d'analyser.
    [switch]$Fix,

    # Reinitialise aussi l'Acces rapide (epingles + recents) de l'Explorateur.
    [switch]$IncludeQuickAccess
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:BackupDir = Join-Path $env:LOCALAPPDATA ("FixDeadPath-backup-{0:yyyyMMdd-HHmmss}" -f (Get-Date))

# Valeurs par defaut des dossiers speciaux. On restaure exactement ce que
# Windows met sur une installation saine, en gardant les variables
# d'environnement (REG_EXPAND_SZ) pour que ca suive le profil.
$script:ShellFolderDefaults = [ordered]@{
    'Desktop'                                 = '%USERPROFILE%\Desktop'
    'Personal'                                = '%USERPROFILE%\Documents'
    'My Pictures'                             = '%USERPROFILE%\Pictures'
    'My Music'                                = '%USERPROFILE%\Music'
    'My Video'                                = '%USERPROFILE%\Videos'
    '{374DE290-123F-4565-9164-39C4925E467B}'  = '%USERPROFILE%\Downloads'
    'Favorites'                               = '%USERPROFILE%\Favorites'
    'AppData'                                 = '%USERPROFILE%\AppData\Roaming'
    'Local AppData'                           = '%USERPROFILE%\AppData\Local'
    'Cache'                                   = '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache'
    'Cookies'                                 = '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies'
    'History'                                 = '%USERPROFILE%\AppData\Local\Microsoft\Windows\History'
    'NetHood'                                 = '%APPDATA%\Microsoft\Windows\Network Shortcuts'
    'PrintHood'                               = '%APPDATA%\Microsoft\Windows\Printer Shortcuts'
    'Programs'                                = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'
    'Recent'                                  = '%APPDATA%\Microsoft\Windows\Recent'
    'SendTo'                                  = '%APPDATA%\Microsoft\Windows\SendTo'
    'Start Menu'                              = '%APPDATA%\Microsoft\Windows\Start Menu'
    'Startup'                                 = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
    'Templates'                               = '%APPDATA%\Microsoft\Windows\Templates'
}


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Emplacement,
        [Parameter(Mandatory)][string]$Element,
        [string]$Valeur,
        [string]$Action,
        [scriptblock]$Repair
    )
    $script:Findings.Add([pscustomobject]@{
        Source      = $Source
        Emplacement = $Emplacement
        Element     = $Element
        Valeur      = $Valeur
        Action      = $Action
        Repair      = $Repair
    })
}

function Test-IsBroken {
    <#  Un chemin est "casse" s'il est renseigne et n'existe pas.
        Si -BadPath est fourni, on ne retient que ce chemin precis.  #>
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    if ([string]::IsNullOrWhiteSpace($expanded)) { return $false }

    if ($BadPath) {
        return $expanded -like "*$BadPath*"
    }

    # On ignore ce qui n'est pas un chemin local absolu (URL, commande nue...)
    if ($expanded -notmatch '^[A-Za-z]:\\') { return $false }
    return -not (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue)
}

function Get-CommandPath {
    <#  Extrait le chemin executable d'une ligne de commande de registre Run,
        qu'elle soit entre guillemets ou non.  #>
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cl = $CommandLine.Trim()
    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"', 1)
        if ($end -gt 1) { return $cl.Substring(1, $end - 1) }
    }
    return ($cl -split '\s+')[0]
}

function Initialize-Backup {
    if (-not (Test-Path -LiteralPath $script:BackupDir)) {
        New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
    }
}

function Backup-RegistryKey {
    param([Parameter(Mandatory)][string]$RegPath)   # ex: HKCU\Software\...
    Initialize-Backup
    $file = Join-Path $script:BackupDir (($RegPath -replace '[\\:]', '_') + '.reg')
    if (-not (Test-Path -LiteralPath $file)) {
        & reg.exe export $RegPath $file /y 2>$null | Out-Null
    }
}

function Backup-File {
    param([Parameter(Mandatory)][string]$FilePath)
    Initialize-Backup
    $sub = Join-Path $script:BackupDir 'fichiers'
    if (-not (Test-Path -LiteralPath $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
    Copy-Item -LiteralPath $FilePath -Destination $sub -Force -ErrorAction SilentlyContinue
}


# ---------------------------------------------------------------------------
# 1. Dossiers speciaux de l'utilisateur  (cause n1 du message)
# ---------------------------------------------------------------------------

function Scan-ShellFolders {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
    )

    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $props = Get-ItemProperty -LiteralPath $key

        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $raw = [string]$p.Value
            if (-not (Test-IsBroken $raw)) { continue }

            $name = $p.Name
            $default = $script:ShellFolderDefaults[$name]
            $keyLocal = $key

            if ($default) {
                $action = "Restaurer -> $default"
                $repair = {
                    Backup-RegistryKey ($keyLocal -replace '^HKCU:', 'HKCU')
                    $target = [Environment]::ExpandEnvironmentVariables($default)
                    if (-not (Test-Path -LiteralPath $target)) {
                        New-Item -ItemType Directory -Path $target -Force | Out-Null
                    }
                    # User Shell Folders doit rester extensible (REG_EXPAND_SZ),
                    # Shell Folders attend un chemin deja resolu (REG_SZ).
                    if ($keyLocal -like '*User Shell Folders*') {
                        Set-ItemProperty -LiteralPath $keyLocal -Name $name -Value $default -Type ExpandString
                    } else {
                        Set-ItemProperty -LiteralPath $keyLocal -Name $name -Value $target -Type String
                    }
                }.GetNewClosure()
            } else {
                $action = 'Inconnu - a verifier manuellement'
                $repair = $null
            }

            Add-Finding -Source 'Dossier special' -Emplacement $key `
                -Element $name -Valeur $raw -Action $action -Repair $repair
        }
    }
}


# ---------------------------------------------------------------------------
# 2. Programmes lances au demarrage (registre)
# ---------------------------------------------------------------------------

function Scan-RunKeys {
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }

        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $key } catch { continue }

        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $cmd = [string]$p.Value
            $exe = Get-CommandPath $cmd
            if (-not (Test-IsBroken $exe)) { continue }

            $name = $p.Name
            $keyLocal = $key
            $isHklm = $key -like 'HKLM:*'

            $repair = if ($isHklm) { $null } else {
                {
                    Backup-RegistryKey ($keyLocal -replace '^HKCU:', 'HKCU')
                    Remove-ItemProperty -LiteralPath $keyLocal -Name $name -Force
                }.GetNewClosure()
            }

            $action = if ($isHklm) {
                'Supprimer (necessite les droits administrateur)'
            } else {
                'Supprimer l entree de demarrage'
            }

            Add-Finding -Source 'Demarrage (registre)' -Emplacement $key `
                -Element $name -Valeur $cmd -Action $action -Repair $repair
        }
    }
}


# ---------------------------------------------------------------------------
# 3. Raccourcis morts (dossier Demarrage, Bureau, menu Demarrer)
# ---------------------------------------------------------------------------

function Scan-Shortcuts {
    $folders = @(
        [Environment]::GetFolderPath('Startup')
        [Environment]::GetFolderPath('Desktop')
        [Environment]::GetFolderPath('Programs')
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    if ($folders.Count -eq 0) { return }

    $shell = New-Object -ComObject WScript.Shell
    try {
        foreach ($folder in $folders) {
            $links = @(Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -Recurse -Force -ErrorAction SilentlyContinue)
            foreach ($link in $links) {
                $target = $null; $workdir = $null
                try {
                    $sc = $shell.CreateShortcut($link.FullName)
                    $target  = $sc.TargetPath
                    $workdir = $sc.WorkingDirectory
                } catch { continue }

                $brokenTarget = Test-IsBroken $target
                $brokenWork   = Test-IsBroken $workdir
                if (-not $brokenTarget -and -not $brokenWork) { continue }

                $linkPath = $link.FullName
                $detail = if ($brokenTarget) { "cible : $target" } else { "dossier de travail : $workdir" }

                # Si seul le dossier de travail est mort, on le vide : le
                # raccourci reste fonctionnel. Si la cible est morte, le
                # raccourci ne sert plus a rien -> mis de cote.
                $repair = if ($brokenTarget) {
                    {
                        Backup-File $linkPath
                        Remove-Item -LiteralPath $linkPath -Force
                    }.GetNewClosure()
                } else {
                    {
                        Backup-File $linkPath
                        $s = (New-Object -ComObject WScript.Shell).CreateShortcut($linkPath)
                        $s.WorkingDirectory = ''
                        $s.Save()
                    }.GetNewClosure()
                }

                $action = if ($brokenTarget) { 'Supprimer le raccourci mort (copie sauvegardee)' }
                          else { 'Vider le dossier de travail' }

                Add-Finding -Source 'Raccourci' -Emplacement $link.DirectoryName `
                    -Element $link.Name -Valeur $detail -Action $action -Repair $repair
            }
        }
    }
    finally {
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}


# ---------------------------------------------------------------------------
# 4. Taches planifiees
# ---------------------------------------------------------------------------

function Scan-ScheduledTasks {
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { return }

    foreach ($task in $tasks) {
        # Les taches Microsoft integrees ne pointent pas vers un profil.
        if ($task.TaskPath -like '\Microsoft\*') { continue }

        foreach ($action in @($task.Actions)) {
            $exe = $null; $wd = $null
            try {
                $exe = $action.Execute
                $wd  = $action.WorkingDirectory
            } catch { continue }

            if (-not (Test-IsBroken $exe) -and -not (Test-IsBroken $wd)) { continue }

            $detail = @(
                if (Test-IsBroken $exe) { "executable : $exe" }
                if (Test-IsBroken $wd)  { "dossier : $wd" }
            ) -join ' | '

            Add-Finding -Source 'Tache planifiee' -Emplacement $task.TaskPath `
                -Element $task.TaskName -Valeur $detail `
                -Action 'A verifier manuellement (Planificateur de taches)' -Repair $null
        }
    }
}


# ---------------------------------------------------------------------------
# 5. Variables d'environnement de l'utilisateur
# ---------------------------------------------------------------------------

function Scan-EnvironmentVariables {
    $key = 'HKCU:\Environment'
    if (-not (Test-Path -LiteralPath $key)) { return }

    $props = Get-ItemProperty -LiteralPath $key
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $val = [string]$p.Value

        # PATH contient plusieurs chemins : on regarde chaque segment.
        if ($p.Name -in @('Path', 'PATH')) {
            $dead = @($val -split ';' | Where-Object { Test-IsBroken $_ })
            if ($dead.Count -eq 0) { continue }

            $name = $p.Name
            $repair = {
                Backup-RegistryKey 'HKCU\Environment'
                $kept = ($val -split ';' | Where-Object { $_ -and -not (Test-IsBroken $_) }) -join ';'
                Set-ItemProperty -LiteralPath 'HKCU:\Environment' -Name $name -Value $kept -Type ExpandString
            }.GetNewClosure()

            Add-Finding -Source 'Variable PATH' -Emplacement $key -Element $name `
                -Valeur ($dead -join ' ; ') -Action 'Retirer les segments morts' -Repair $repair
            continue
        }

        if (-not (Test-IsBroken $val)) { continue }

        $name = $p.Name
        $repair = {
            Backup-RegistryKey 'HKCU\Environment'
            Remove-ItemProperty -LiteralPath 'HKCU:\Environment' -Name $name -Force
        }.GetNewClosure()

        Add-Finding -Source 'Variable utilisateur' -Emplacement $key -Element $name `
            -Valeur $val -Action 'Supprimer la variable' -Repair $repair
    }
}


# ---------------------------------------------------------------------------
# 6. Acces rapide de l'Explorateur (optionnel)
# ---------------------------------------------------------------------------

function Reset-QuickAccess {
    # Ces deux fichiers memorisent les dossiers epingles et recents. Quand ils
    # referencent un dossier supprime, l'Explorateur affiche l'erreur a chaque
    # ouverture. Les supprimer reinitialise l'Acces rapide sans autre effet.
    $base = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
    $targets = @(
        Join-Path $base 'AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms'
        Join-Path $base 'AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms'
    )

    $done = 0
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        Backup-File $t
        try {
            Remove-Item -LiteralPath $t -Force
            $done++
        } catch {
            Write-Host "  Impossible de supprimer $t (Explorateur ouvert ?) : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "  Acces rapide : $done fichier(s) reinitialise(s)." -ForegroundColor Green
}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '===== Recherche des references vers un dossier supprime =====' -ForegroundColor Cyan
if ($BadPath) { Write-Host "Chemin recherche : $BadPath" }
else          { Write-Host 'Mode : toute reference vers un dossier inexistant' }
Write-Host ''

Scan-ShellFolders
Scan-RunKeys
Scan-Shortcuts
Scan-ScheduledTasks
Scan-EnvironmentVariables

if ($script:Findings.Count -eq 0) {
    Write-Host 'Aucune reference cassee trouvee dans les emplacements analyses.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Si le message persiste, il vient probablement de l Acces rapide :' -ForegroundColor Yellow
    Write-Host '  .\Fix-DeadProfilePath.ps1 -Fix -IncludeQuickAccess'
    Write-Host ''
    if ($Fix -and $IncludeQuickAccess) {
        Write-Host 'Reinitialisation de l Acces rapide...' -ForegroundColor Cyan
        Reset-QuickAccess
        Write-Host ''
        Write-Host 'Redemarre l Explorateur pour appliquer :' -ForegroundColor Cyan
        Write-Host '  Stop-Process -Name explorer -Force'
        Write-Host ''
    }
    return
}

$script:Findings |
    Select-Object Source, Element, Valeur, Action |
    Format-Table -AutoSize -Wrap

Write-Host ("Total : {0} reference(s) cassee(s)." -f $script:Findings.Count) -ForegroundColor Yellow
Write-Host ''

if (-not $Fix) {
    Write-Host 'Mode analyse : rien n a ete modifie.' -ForegroundColor Cyan
    Write-Host 'Pour appliquer les corrections ci-dessus :' -ForegroundColor Cyan
    Write-Host '  .\Fix-DeadProfilePath.ps1 -Fix -IncludeQuickAccess'
    Write-Host ''
    return
}

# --- Application des corrections ---

Write-Host 'Application des corrections...' -ForegroundColor Cyan
Initialize-Backup
Write-Host "Sauvegarde : $script:BackupDir"
Write-Host ''

$ok = 0; $skipped = 0; $failed = 0

foreach ($f in $script:Findings) {
    if (-not $f.Repair) {
        Write-Host ("  [ IGNORE ] {0} / {1} - {2}" -f $f.Source, $f.Element, $f.Action) -ForegroundColor DarkYellow
        $skipped++
        continue
    }
    try {
        & $f.Repair
        Write-Host ("  [   OK   ] {0} / {1}" -f $f.Source, $f.Element) -ForegroundColor Green
        $ok++
    } catch {
        Write-Host ("  [ ECHEC  ] {0} / {1} : {2}" -f $f.Source, $f.Element, $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
}

if ($IncludeQuickAccess) {
    Write-Host ''
    Write-Host 'Reinitialisation de l Acces rapide...' -ForegroundColor Cyan
    Reset-QuickAccess
}

Write-Host ''
Write-Host ("Termine : {0} corrigee(s), {1} ignoree(s), {2} en echec." -f $ok, $skipped, $failed) -ForegroundColor Cyan
Write-Host "Sauvegarde conservee dans : $script:BackupDir"
Write-Host ''
Write-Host 'Derniere etape - redemarre l Explorateur (ou le PC) :' -ForegroundColor Cyan
Write-Host '  Stop-Process -Name explorer -Force'
Write-Host ''
