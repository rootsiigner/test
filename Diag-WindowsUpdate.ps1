<#
.SYNOPSIS
    Diagnostic complet de Windows Update sur Windows 10/11 : trouve pourquoi
    les mises a jour echouent ou ne s'installent pas.

.DESCRIPTION
    Passe en revue, dans l'ordre des causes les plus frequentes :
      1. Version et etat du systeme
      2. Espace disque (systeme + partition de recuperation)
      3. Services necessaires a Windows Update
      4. Strategies, pause et blocages configures
      5. Redemarrage en attente
      6. Historique des echecs, avec decodage des codes d'erreur
      7. Sante du magasin de composants
      8. Eligibilite materielle (pour les mises a jour de fonctionnalites)

    Par defaut : LECTURE SEULE. Aucun changement n'est applique.
    Le mode -Repair effectue la reinitialisation standard des composants
    Windows Update (necessite les droits administrateur).

.EXAMPLE
    .\Diag-WindowsUpdate.ps1
    Diagnostic complet. Affiche un verdict et les actions recommandees.

.EXAMPLE
    .\Diag-WindowsUpdate.ps1 -Repair
    Applique la reinitialisation des composants Windows Update.
    A lancer dans un PowerShell ouvert en tant qu'administrateur.

.NOTES
    Lance-le de preference en administrateur : certaines verifications
    (magasin de composants, Secure Boot, partition de recuperation) sont
    inaccessibles autrement. Le script fonctionne quand meme sans, en
    signalant ce qu'il n'a pas pu lire.
#>
[CmdletBinding()]
param(
    # Applique la reinitialisation des composants Windows Update.
    [switch]$Repair,

    # Nombre d'entrees d'historique a analyser.
    [ValidateRange(10, 500)]
    [int]$HistoryCount = 80
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:Issues = New-Object System.Collections.Generic.List[object]
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)


# ---------------------------------------------------------------------------
# Dictionnaire des codes d'erreur Windows Update les plus courants
# ---------------------------------------------------------------------------

$script:ErrorCodes = @{
    '0x80070002' = @{ Cause = 'Fichiers de mise a jour manquants ou cache corrompu'; Fix = 'Reinitialiser les composants : .\Diag-WindowsUpdate.ps1 -Repair' }
    '0x80070003' = @{ Cause = 'Cache Windows Update corrompu'; Fix = 'Reinitialiser les composants : -Repair' }
    '0x8007000D' = @{ Cause = 'Donnees de mise a jour invalides'; Fix = 'Reinitialiser les composants, puis DISM /RestoreHealth' }
    '0x80070020' = @{ Cause = 'Fichier verrouille par un autre programme (souvent l antivirus)'; Fix = 'Desactiver temporairement l antivirus tiers, puis reessayer' }
    '0x80070070' = @{ Cause = 'Espace disque insuffisant'; Fix = 'Liberer de l espace sur C: (voir section Espace disque)' }
    '0x800705B4' = @{ Cause = 'Delai d attente depasse'; Fix = 'Reessayer sur une connexion stable, hors VPN' }
    '0x80070422' = @{ Cause = 'Le service Windows Update est desactive'; Fix = 'Reactiver le service (voir section Services)' }
    '0x80070643' = @{ Cause = 'Echec d installation - tres souvent la partition de recuperation (WinRE) trop petite'; Fix = 'Voir la section Partition de recuperation ci-dessous' }
    '0x80073712' = @{ Cause = 'Magasin de composants Windows corrompu'; Fix = 'DISM /Online /Cleanup-Image /RestoreHealth puis sfc /scannow' }
    '0x800F0831' = @{ Cause = 'Un correctif intermediaire manque dans le magasin'; Fix = 'DISM /RestoreHealth, ou installer le dernier cumul manuellement depuis le catalogue Microsoft' }
    '0x800F0922' = @{ Cause = 'Partition systeme reservee trop petite, ou VPN actif'; Fix = 'Deconnecter tout VPN et reessayer ; sinon agrandir la partition systeme' }
    '0x800F0805' = @{ Cause = 'Package de mise a jour invalide'; Fix = 'Retelecharger : reinitialiser les composants (-Repair)' }
    '0x8024402C' = @{ Cause = 'Impossible de joindre les serveurs Microsoft (proxy / DNS)'; Fix = 'Verifier proxy et DNS ; desactiver le VPN' }
    '0x80244022' = @{ Cause = 'Serveur de mise a jour injoignable ou occupe'; Fix = 'Reessayer plus tard ; verifier un eventuel WSUS d entreprise' }
    '0x80248007' = @{ Cause = 'Conditions de licence introuvables / base de donnees WU abimee'; Fix = 'Reinitialiser les composants (-Repair)' }
    '0x80240034' = @{ Cause = 'Echec du telechargement'; Fix = 'Reinitialiser les composants ; verifier la connexion' }
    '0x80240FFF' = @{ Cause = 'Erreur interne Windows Update'; Fix = 'Reinitialiser les composants (-Repair)' }
    '0xC1900101' = @{ Cause = 'Pilote incompatible pendant la mise a niveau'; Fix = 'Mettre a jour les pilotes (surtout carte graphique et stockage), debrancher les peripheriques USB' }
    '0xC1900208' = @{ Cause = 'Application incompatible bloque la mise a niveau'; Fix = 'Desinstaller les antivirus tiers et logiciels de chiffrement disque, puis reessayer' }
    '0xC1900200' = @{ Cause = 'Le PC ne remplit pas la configuration minimale'; Fix = 'Voir la section Eligibilite materielle' }
    '0xC190020E' = @{ Cause = 'Espace disque insuffisant pour la mise a niveau'; Fix = 'Liberer au moins 25 Go sur C:' }
}

function Resolve-UpdateError {
    param([string]$Code)
    if ($script:ErrorCodes.ContainsKey($Code)) { return $script:ErrorCodes[$Code] }
    return $null
}


# ---------------------------------------------------------------------------
# Utilitaires d'affichage
# ---------------------------------------------------------------------------

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ("=== {0} " -f $Title).PadRight(72, '=') -ForegroundColor Cyan
}

function Write-Line {
    param([string]$Label, $Value, [string]$Status = 'info')
    $color = switch ($Status) {
        'ok'    { 'Green' }
        'warn'  { 'Yellow' }
        'bad'   { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("  {0,-34} " -f $Label) -NoNewline
    Write-Host $Value -ForegroundColor $color
}

function Add-Issue {
    param(
        [Parameter(Mandatory)][ValidateSet('BLOQUANT', 'IMPORTANT', 'A VERIFIER')][string]$Severity,
        [Parameter(Mandatory)][string]$Problem,
        [Parameter(Mandatory)][string]$Action
    )
    $script:Issues.Add([pscustomobject]@{
        Severity = $Severity; Problem = $Problem; Action = $Action
    })
}


# ---------------------------------------------------------------------------
# 1. Etat du systeme
# ---------------------------------------------------------------------------

function Test-SystemState {
    Write-Section 'Systeme'

    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = "$($cv.CurrentBuild).$($cv.UBR)"
    $display = if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $cv.DisplayVersion } else { $cv.ReleaseId }

    Write-Line 'Edition'        $cv.ProductName
    Write-Line 'Version'        $display
    Write-Line 'Build'          $build
    Write-Line 'Administrateur' $(if ($script:IsAdmin) { 'Oui' } else { 'Non - certains tests seront ignores' }) `
                                $(if ($script:IsAdmin) { 'ok' } else { 'warn' })

    if (-not $script:IsAdmin) {
        Add-Issue 'A VERIFIER' 'Script lance sans droits administrateur' `
            'Relance PowerShell en tant qu administrateur pour un diagnostic complet'
    }

    # Date de la derniere mise a jour reellement installee.
    try {
        $last = Get-HotFix -ErrorAction Stop |
            Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($last) {
            $days = [int]((Get-Date) - $last.InstalledOn).TotalDays
            $st = if ($days -gt 75) { 'bad' } elseif ($days -gt 45) { 'warn' } else { 'ok' }
            Write-Line 'Derniere MAJ installee' ("{0} ({1}, il y a {2} jours)" -f $last.HotFixID, $last.InstalledOn.ToString('dd/MM/yyyy'), $days) $st
            if ($days -gt 75) {
                Add-Issue 'IMPORTANT' "Aucune mise a jour installee depuis $days jours" `
                    'Le PC a rate plusieurs cumuls mensuels - la cause est probablement listee plus bas'
            }
        }
    } catch {
        Write-Line 'Derniere MAJ installee' 'illisible' 'warn'
    }
}


# ---------------------------------------------------------------------------
# 2. Espace disque
# ---------------------------------------------------------------------------

function Test-DiskSpace {
    Write-Section 'Espace disque'

    $sys = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
    $freeGB  = [math]::Round($sys.FreeSpace / 1GB, 1)
    $totalGB = [math]::Round($sys.Size / 1GB, 1)

    # Un cumul mensuel demande ~10 Go de marge ; une mise a niveau de version
    # (23H2 -> 24H2 par exemple) en demande environ 25 Go.
    $st = if ($freeGB -lt 10) { 'bad' } elseif ($freeGB -lt 25) { 'warn' } else { 'ok' }
    Write-Line "Libre sur $($env:SystemDrive)" "$freeGB Go / $totalGB Go" $st

    if ($freeGB -lt 10) {
        Add-Issue 'BLOQUANT' "Seulement $freeGB Go libres sur $($env:SystemDrive)" `
            'Libere au moins 15 Go : Parametres > Systeme > Stockage > Recommandations de nettoyage'
    } elseif ($freeGB -lt 25) {
        Add-Issue 'A VERIFIER' "$freeGB Go libres - suffisant pour un cumul, juste pour une mise a niveau de version" `
            'Prevois 25 Go libres si Windows propose une nouvelle version (24H2, 25H2...)'
    }

    # Taille du cache de telechargement : au-dela de quelques Go, il est
    # souvent corrompu et empeche tout nouveau telechargement.
    $sd = Join-Path $env:SystemRoot 'SoftwareDistribution\Download'
    if (Test-Path -LiteralPath $sd) {
        try {
            $size = [math]::Round((Get-ChildItem -LiteralPath $sd -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object Length -Sum).Sum / 1GB, 2)
            $st = if ($size -gt 8) { 'warn' } else { 'info' }
            Write-Line 'Cache SoftwareDistribution' "$size Go" $st
            if ($size -gt 8) {
                Add-Issue 'A VERIFIER' "Cache de telechargement volumineux ($size Go)" `
                    'Souvent le signe de telechargements rates empiles : lance -Repair'
            }
        } catch { }
    }

    # Partition de recuperation : cause n1 du code 0x80070643 depuis 2024.
    if ($script:IsAdmin) {
        try {
            $re = & reagentc.exe /info 2>&1 | Out-String
            $enabled = $re -match 'Enabled|Activ'
            Write-Line 'Environnement de recuperation' $(if ($enabled) { 'Actif' } else { 'Desactive' }) `
                                                        $(if ($enabled) { 'ok' } else { 'warn' })
            if (-not $enabled) {
                Add-Issue 'A VERIFIER' 'WinRE desactive' `
                    'Si tu vois le code 0x80070643 : la partition de recuperation est trop petite. Voir la note en fin de rapport.'
            }
        } catch {
            Write-Line 'Environnement de recuperation' 'illisible' 'warn'
        }
    }
}


# ---------------------------------------------------------------------------
# 3. Services
# ---------------------------------------------------------------------------

function Test-Services {
    Write-Section 'Services Windows Update'

    # wuauserv et bits doivent pouvoir demarrer ; les autres sont necessaires
    # a la validation et l'installation des paquets.
    $required = [ordered]@{
        'wuauserv'       = 'Windows Update'
        'bits'           = 'Transfert intelligent en arriere-plan (telechargement)'
        'cryptsvc'       = 'Services de chiffrement (verification des signatures)'
        'msiserver'      = 'Windows Installer'
        'TrustedInstaller' = 'Programme d installation des modules Windows'
        'DoSvc'          = 'Optimisation de la distribution'
    }

    foreach ($name in $required.Keys) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Line $name 'INTROUVABLE' 'bad'
            Add-Issue 'BLOQUANT' "Le service $name est absent du systeme" `
                'Systeme endommage : lance DISM /Online /Cleanup-Image /RestoreHealth'
            continue
        }

        $startType = 'inconnu'
        try {
            $wmi = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            $startType = $wmi.StartMode
        } catch { }

        $disabled = $startType -eq 'Disabled'
        $st = if ($disabled) { 'bad' } elseif ($svc.Status -eq 'Running') { 'ok' } else { 'info' }
        Write-Line $name "$($svc.Status) / demarrage : $startType" $st

        if ($disabled) {
            Add-Issue 'BLOQUANT' "Le service '$($required[$name])' ($name) est DESACTIVE" `
                "En administrateur : Set-Service -Name $name -StartupType Manual ; Start-Service $name"
        }
    }
}


# ---------------------------------------------------------------------------
# 4. Strategies et blocages
# ---------------------------------------------------------------------------

function Test-Policies {
    Write-Section 'Strategies et blocages'

    $found = $false

    # Mises a jour en pause depuis les Parametres.
    $ux = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\UX\Settings'
    if (Test-Path -LiteralPath $ux) {
        $s = Get-ItemProperty -LiteralPath $ux
        foreach ($field in @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime')) {
            if ($s.PSObject.Properties.Name -notcontains $field) { continue }
            $raw = [string]$s.$field
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            try {
                $until = [datetime]::Parse($raw).ToLocalTime()
                if ($until -gt (Get-Date)) {
                    $found = $true
                    Write-Line 'Mises a jour en PAUSE' ("jusqu au {0:dd/MM/yyyy HH:mm}" -f $until) 'bad'
                    Add-Issue 'BLOQUANT' "Les mises a jour sont en pause jusqu au $($until.ToString('dd/MM/yyyy'))" `
                        'Parametres > Windows Update > Reprendre les mises a jour'
                }
            } catch { }
        }
    }

    # Strategies de groupe / registre.
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (Test-Path -LiteralPath $pol) {
        $p = Get-ItemProperty -LiteralPath $pol
        $names = $p.PSObject.Properties.Name

        if ($names -contains 'WUServer') {
            $found = $true
            Write-Line 'Serveur WSUS impose' $p.WUServer 'warn'
            Add-Issue 'IMPORTANT' "Le PC est dirige vers un serveur de mise a jour interne ($($p.WUServer))" `
                'Si ce PC n est plus dans le reseau d entreprise, ce serveur est injoignable : il faut retirer cette strategie'
        }
        if ($names -contains 'TargetReleaseVersionInfo') {
            $found = $true
            Write-Line 'Version bloquee sur' $p.TargetReleaseVersionInfo 'warn'
            Add-Issue 'IMPORTANT' "Windows est verrouille sur la version $($p.TargetReleaseVersionInfo)" `
                'Aucune version plus recente ne sera proposee tant que cette strategie existe'
        }
        foreach ($d in @('DeferFeatureUpdatesPeriodInDays', 'DeferQualityUpdatesPeriodInDays')) {
            if ($names -contains $d -and [int]$p.$d -gt 0) {
                $found = $true
                Write-Line $d "$($p.$d) jours" 'warn'
            }
        }
        $au = Join-Path $pol 'AU'
        if (Test-Path -LiteralPath $au) {
            $a = Get-ItemProperty -LiteralPath $au
            if ($a.PSObject.Properties.Name -contains 'NoAutoUpdate' -and [int]$a.NoAutoUpdate -eq 1) {
                $found = $true
                Write-Line 'Mise a jour automatique' 'DESACTIVEE par strategie' 'bad'
                Add-Issue 'BLOQUANT' 'Une strategie desactive completement la mise a jour automatique' `
                    'Supprimer NoAutoUpdate dans HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            }
        }
    }

    # Connexion limitee : Windows ne telecharge pas les gros paquets dessus.
    try {
        $cost = Get-CimInstance -Namespace 'root\StandardCimv2' -ClassName MSFT_NetConnectionProfile -ErrorAction Stop |
            Where-Object { $_.IPv4Connectivity -eq 4 -or $_.IPv6Connectivity -eq 4 }
        # 1 = illimite, 2 = limite (fixe), 4 = limite (variable)
        $metered = $cost | Where-Object { $_.NetworkCategory -ne $null -and $_.PSObject.Properties.Name -contains 'IsMetered' -and $_.IsMetered }
        if ($metered) {
            $found = $true
            Write-Line 'Connexion reseau' 'LIMITEE (metered)' 'warn'
            Add-Issue 'IMPORTANT' 'La connexion est declaree limitee' `
                'Parametres > Reseau > Proprietes de la connexion > desactiver "Connexion limitee"'
        }
    } catch { }

    if (-not $found) {
        Write-Line 'Strategies restrictives' 'aucune detectee' 'ok'
    }
}


# ---------------------------------------------------------------------------
# 5. Redemarrage en attente
# ---------------------------------------------------------------------------

function Test-PendingReboot {
    Write-Section 'Redemarrage en attente'

    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'installation de composants en cours'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'Windows Update attend un redemarrage'
    }
    try {
        $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if ($sm.PSObject.Properties.Name -contains 'PendingFileRenameOperations' -and $sm.PendingFileRenameOperations) {
            $reasons += 'fichiers a remplacer au prochain demarrage'
        }
    } catch { }

    if ($reasons.Count -gt 0) {
        Write-Line 'Redemarrage requis' ($reasons -join ' ; ') 'bad'
        Add-Issue 'BLOQUANT' 'Un redemarrage est en attente' `
            'Windows refuse d installer de nouvelles mises a jour tant que le redemarrage n est pas fait. Redemarre, puis relance ce diagnostic.'
    } else {
        Write-Line 'Redemarrage requis' 'non' 'ok'
    }
}


# ---------------------------------------------------------------------------
# 6. Historique des echecs
# ---------------------------------------------------------------------------

function Test-UpdateHistory {
    Write-Section 'Historique des mises a jour'

    $history = @()
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total    = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $history = @($searcher.QueryHistory(0, [Math]::Min($total, $HistoryCount)))
        }
    } catch {
        Write-Line 'Historique' "illisible : $($_.Exception.Message)" 'warn'
        return
    }

    if ($history.Count -eq 0) {
        Write-Line 'Historique' 'vide' 'warn'
        Add-Issue 'A VERIFIER' 'Aucun historique de mise a jour' `
            'Base de donnees Windows Update probablement reinitialisee ou corrompue : lance -Repair'
        return
    }

    # ResultCode : 2 = reussi, 3 = reussi avec erreurs, 4 = echec, 5 = annule
    $failed = @($history | Where-Object { $_.ResultCode -in @(4, 5) })
    $ok     = @($history | Where-Object { $_.ResultCode -eq 2 })

    Write-Line 'Entrees analysees' $history.Count
    Write-Line 'Reussies'          $ok.Count 'ok'
    Write-Line 'En echec'          $failed.Count $(if ($failed.Count -gt 0) { 'bad' } else { 'ok' })

    if ($failed.Count -eq 0) { return }

    Write-Host ''
    Write-Host '  Derniers echecs :' -ForegroundColor Yellow

    $recent = $failed | Sort-Object Date -Descending | Select-Object -First 8
    foreach ($f in $recent) {
        $code = '0x{0:X8}' -f ($f.HResult -band 0xFFFFFFFF)
        $title = if ($f.Title.Length -gt 62) { $f.Title.Substring(0, 59) + '...' } else { $f.Title }
        Write-Host ("    {0:dd/MM/yyyy}  {1}  {2}" -f $f.Date, $code, $title) -ForegroundColor Gray
    }

    # On remonte les codes les plus frequents : c'est la vraie cause.
    Write-Host ''
    Write-Host '  Codes d erreur rencontres :' -ForegroundColor Yellow

    $byCode = $failed |
        Group-Object { '0x{0:X8}' -f ($_.HResult -band 0xFFFFFFFF) } |
        Sort-Object Count -Descending

    foreach ($g in $byCode) {
        $info = Resolve-UpdateError $g.Name
        Write-Host ("    {0}  x{1}" -f $g.Name, $g.Count) -ForegroundColor Red
        if ($info) {
            Write-Host ("        Cause  : {0}" -f $info.Cause) -ForegroundColor Gray
            Write-Host ("        Remede : {0}" -f $info.Fix) -ForegroundColor Green
            Add-Issue 'BLOQUANT' "$($g.Name) - $($info.Cause)" $info.Fix
        } else {
            Write-Host '        Code non repertorie.' -ForegroundColor Gray
            Add-Issue 'A VERIFIER' "Code d erreur $($g.Name) ($($g.Count) fois)" `
                "Recherche '$($g.Name) windows update' sur support.microsoft.com"
        }
    }
}


# ---------------------------------------------------------------------------
# 7. Sante du magasin de composants
# ---------------------------------------------------------------------------

function Test-ComponentStore {
    Write-Section 'Magasin de composants'

    if (-not $script:IsAdmin) {
        Write-Line 'Verification' 'ignoree (droits administrateur requis)' 'warn'
        return
    }

    Write-Host '  Analyse en cours (1 a 3 minutes)...' -ForegroundColor Gray
    try {
        $out = & dism.exe /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String

        if ($out -match 'No component store corruption|Aucune corruption') {
            Write-Line 'Etat' 'sain' 'ok'
        }
        elseif ($out -match 'repairable|reparable') {
            Write-Line 'Etat' 'CORROMPU mais reparable' 'bad'
            Add-Issue 'BLOQUANT' 'Le magasin de composants Windows est corrompu' `
                'En administrateur : DISM /Online /Cleanup-Image /RestoreHealth  puis  sfc /scannow  puis redemarre'
        }
        elseif ($out -match 'not repairable|non reparable') {
            Write-Line 'Etat' 'CORROMPU et non reparable localement' 'bad'
            Add-Issue 'BLOQUANT' 'Magasin de composants irreparable par DISM seul' `
                'Reparation par mise a niveau : telecharge l ISO Windows 11, monte-le, lance setup.exe et choisis "Conserver fichiers et applications"'
        }
        else {
            Write-Line 'Etat' 'resultat non concluant' 'warn'
        }
    } catch {
        Write-Line 'Etat' "echec de l analyse : $($_.Exception.Message)" 'warn'
    }
}


# ---------------------------------------------------------------------------
# 8. Eligibilite materielle (mises a niveau de version)
# ---------------------------------------------------------------------------

function Test-Hardware {
    Write-Section 'Eligibilite materielle'

    # TPM 2.0
    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
        if ($tpm) {
            $ver = ($tpm.SpecVersion -split ',')[0].Trim()
            $okTpm = $tpm.IsEnabled_InitialValue -and ([double]$ver -ge 2.0)
            Write-Line 'TPM' ("version $ver, active : $($tpm.IsEnabled_InitialValue)") $(if ($okTpm) { 'ok' } else { 'bad' })
            if (-not $okTpm) {
                Add-Issue 'IMPORTANT' "TPM absent, desactive ou trop ancien (version $ver)" `
                    'Active le TPM (parfois nomme PTT chez Intel, fTPM chez AMD) dans le BIOS/UEFI'
            }
        }
    } catch {
        Write-Line 'TPM' 'non detecte ou illisible' 'warn'
    }

    # Secure Boot
    if ($script:IsAdmin) {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            Write-Line 'Secure Boot' $(if ($sb) { 'active' } else { 'desactive' }) $(if ($sb) { 'ok' } else { 'warn' })
            if (-not $sb) {
                Add-Issue 'A VERIFIER' 'Secure Boot desactive' `
                    'Requis par Windows 11 : active-le dans le BIOS/UEFI (le disque doit etre en GPT)'
            }
        } catch {
            Write-Line 'Secure Boot' 'indisponible (BIOS hérité / non-UEFI)' 'warn'
        }
    } else {
        Write-Line 'Secure Boot' 'ignore (droits administrateur requis)' 'warn'
    }

    $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    Write-Line 'Memoire installee' "$ram Go" $(if ($ram -ge 4) { 'ok' } else { 'bad' })
}


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

function Show-Verdict {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host ' VERDICT' -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan

    if ($script:Issues.Count -eq 0) {
        Write-Host ''
        Write-Host '  Aucun blocage detecte.' -ForegroundColor Green
        Write-Host '  Si Windows Update echoue quand meme, relance le diagnostic'
        Write-Host '  juste apres une tentative de mise a jour : le code d erreur'
        Write-Host '  apparaitra alors dans l historique.'
        Write-Host ''
        return
    }

    foreach ($sev in @('BLOQUANT', 'IMPORTANT', 'A VERIFIER')) {
        $group = @($script:Issues | Where-Object { $_.Severity -eq $sev })
        if ($group.Count -eq 0) { continue }

        $color = switch ($sev) { 'BLOQUANT' { 'Red' } 'IMPORTANT' { 'Yellow' } default { 'Gray' } }
        Write-Host ''
        Write-Host ("  --- {0} ({1}) ---" -f $sev, $group.Count) -ForegroundColor $color

        $i = 1
        foreach ($issue in $group) {
            Write-Host ("  {0}. {1}" -f $i, $issue.Problem) -ForegroundColor $color
            Write-Host ("     -> {0}" -f $issue.Action) -ForegroundColor Green
            $i++
        }
    }

    Write-Host ''
    Write-Host '  Traite les points BLOQUANT en premier, dans l ordre, en'
    Write-Host '  relancant ce diagnostic apres chacun.'
    Write-Host ''

    if ($script:Issues | Where-Object { $_.Problem -like '*0x80070643*' }) {
        Write-Host '  Note sur 0x80070643 :' -ForegroundColor Yellow
        Write-Host '  Ce code vient presque toujours d une partition de recuperation'
        Write-Host '  trop petite (il faut ~750 Mo libres). Microsoft documente la'
        Write-Host '  procedure d agrandissement dans l article KB5028997 - c est une'
        Write-Host '  manipulation de partitions, sauvegarde tes donnees avant.'
        Write-Host ''
    }
}


# ---------------------------------------------------------------------------
# Reparation : reinitialisation des composants Windows Update
# ---------------------------------------------------------------------------

function Invoke-UpdateRepair {
    Write-Section 'Reinitialisation des composants Windows Update'

    if (-not $script:IsAdmin) {
        Write-Host '  Droits administrateur requis.' -ForegroundColor Red
        Write-Host '  Ferme cette fenetre, ouvre PowerShell en tant qu administrateur,'
        Write-Host '  et relance :  .\Diag-WindowsUpdate.ps1 -Repair'
        Write-Host ''
        return
    }

    $services = @('wuauserv', 'bits', 'cryptsvc', 'msiserver')
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    Write-Host '  Arret des services...' -ForegroundColor Gray
    foreach ($s in $services) {
        try { Stop-Service -Name $s -Force -ErrorAction Stop; Write-Host "    $s arrete" -ForegroundColor Gray }
        catch { Write-Host "    $s : $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    # On renomme au lieu de supprimer : Windows recree des dossiers neufs, et
    # les anciens restent recuperables si besoin.
    Write-Host '  Mise de cote des caches...' -ForegroundColor Gray
    foreach ($item in @(
        @{ Path = (Join-Path $env:SystemRoot 'SoftwareDistribution'); New = "SoftwareDistribution.old-$stamp" }
        @{ Path = (Join-Path $env:SystemRoot 'System32\catroot2');    New = "catroot2.old-$stamp" }
    )) {
        if (-not (Test-Path -LiteralPath $item.Path)) { continue }
        try {
            Rename-Item -LiteralPath $item.Path -NewName $item.New -Force -ErrorAction Stop
            Write-Host "    $(Split-Path $item.Path -Leaf) -> $($item.New)" -ForegroundColor Green
        } catch {
            Write-Host "    $(Split-Path $item.Path -Leaf) : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host '  Redemarrage des services...' -ForegroundColor Gray
    foreach ($s in $services) {
        try { Start-Service -Name $s -ErrorAction Stop; Write-Host "    $s demarre" -ForegroundColor Green }
        catch { Write-Host "    $s : $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    Write-Host ''
    Write-Host '  Reinitialisation terminee.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Suite :' -ForegroundColor Cyan
    Write-Host '    1. Redemarre le PC'
    Write-Host '    2. Parametres > Windows Update > Rechercher des mises a jour'
    Write-Host '    3. Le premier passage est lent (tout le catalogue est retelecharge)'
    Write-Host ''
    Write-Host "  Les anciens caches sont conserves sous $env:SystemRoot (*.old-$stamp)."
    Write-Host '  Tu peux les supprimer une fois les mises a jour reussies.'
    Write-Host ''
}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '############################################################' -ForegroundColor Cyan
Write-Host '#     DIAGNOSTIC WINDOWS UPDATE                            #' -ForegroundColor Cyan
Write-Host '############################################################' -ForegroundColor Cyan

Test-SystemState
Test-DiskSpace
Test-Services
Test-Policies
Test-PendingReboot
Test-UpdateHistory
Test-ComponentStore
Test-Hardware
Show-Verdict

if ($Repair) {
    Invoke-UpdateRepair
} else {
    Write-Host '  Reinitialisation des composants (si recommandee ci-dessus) :' -ForegroundColor Cyan
    Write-Host '    PowerShell EN ADMINISTRATEUR, puis :'
    Write-Host '    .\Diag-WindowsUpdate.ps1 -Repair'
    Write-Host ''
}
