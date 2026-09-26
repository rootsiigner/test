<#
.SYNOPSIS
    PCWatch - Moniteur de performance continu pour Windows 10/11.

.DESCRIPTION
    Echantillonne CPU / memoire / disque a intervalle regulier, journalise tout
    en CSV, et enregistre une "alerte" (avec les processus responsables) chaque
    fois qu'un ralentissement est detecte.

    N'a PAS besoin de droits administrateur.
    Compatible Windows PowerShell 5.1 (installe par defaut) et PowerShell 7+.
    Utilise les classes WMI (invariantes) plutot que Get-Counter, pour
    fonctionner sur un Windows en francais comme en anglais.

.EXAMPLE
    .\PCWatch.ps1 -Install
    Installe la surveillance : demarre maintenant et a chaque ouverture de session.

.EXAMPLE
    .\PCWatch.ps1 -Report
    Affiche le bilan des 7 derniers jours : pics, frequence, processus coupables.

.EXAMPLE
    .\PCWatch.ps1
    Lance la surveillance au premier plan (Ctrl+C pour arreter).

.EXAMPLE
    .\PCWatch.ps1 -Uninstall
    Supprime la tache planifiee (les journaux sont conserves).
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    # --- Reglages de la surveillance ---
    [ValidateRange(5, 3600)]
    [int]$IntervalSeconds = 30,

    # Seuils de declenchement d'une alerte (en %)
    [ValidateRange(1, 100)][int]$CpuThreshold  = 85,
    [ValidateRange(1, 100)][int]$MemThreshold  = 88,
    [ValidateRange(1, 100)][int]$DiskThreshold = 85,

    # Nombre d'echantillons consecutifs au-dessus du seuil avant d'alerter
    # (evite de signaler chaque micro-pic sans consequence)
    [ValidateRange(1, 20)][int]$SustainedSamples = 2,

    # Duree de conservation des journaux, en jours
    [ValidateRange(1, 365)][int]$KeepDays = 21,

    [string]$LogDirectory = (Join-Path $env:LOCALAPPDATA 'PCWatch'),

    # --- Modes ---
    [Parameter(ParameterSetName = 'Report')][switch]$Report,
    [Parameter(ParameterSetName = 'Report')][ValidateRange(1, 365)][int]$ReportDays = 7,
    [Parameter(ParameterSetName = 'Install')][switch]$Install,
    [Parameter(ParameterSetName = 'Uninstall')][switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:TaskName = 'PCWatch'
$script:LogicalCores = [Math]::Max(1, [int]$env:NUMBER_OF_PROCESSORS)

# Processus systeme qu'il est normal de voir consommer : on les signale quand
# meme, mais annotes, pour ne pas envoyer l'utilisateur sur une fausse piste.
$script:KnownSystem = @{
    'MsMpEng'            = 'Antivirus Microsoft Defender (analyse en cours)'
    'TiWorker'           = 'Maintenance des composants Windows (Windows Update)'
    'TrustedInstaller'   = 'Installation de mises a jour Windows'
    'SearchIndexer'      = 'Indexation de la recherche Windows'
    'MoUsoCoreWorker'    = 'Orchestrateur Windows Update'
    'wuauclt'            = 'Client Windows Update'
    'CompatTelRunner'    = 'Telemetrie de compatibilite Microsoft'
    'System'             = 'Noyau Windows / pilotes'
    'Memory Compression' = 'Compression memoire Windows (signe de RAM saturee)'
    'dwm'                = 'Gestionnaire de fenetres (affichage)'
    'explorer'           = 'Explorateur Windows / bureau'
}


# ---------------------------------------------------------------------------
# Collecte
# ---------------------------------------------------------------------------

function Get-SystemSnapshot {
    <#  Renvoie un instantane des compteurs globaux. Toute valeur illisible
        vaut $null plutot que de faire echouer la boucle.  #>
    $snap = [ordered]@{
        Timestamp    = (Get-Date).ToString('s')
        CpuPct       = $null
        MemPct       = $null
        MemAvailMB   = $null
        DiskPct      = $null
        DiskQueue    = $null
        PagesPerSec  = $null
        FreeSpaceGB  = $null
    }

    try {
        $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor `
            -Filter "Name='_Total'" -ErrorAction Stop
        $snap.CpuPct = [math]::Round([double]$cpu.PercentProcessorTime, 1)
    } catch { Write-Verbose "CPU illisible : $_" }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalKB = [double]$os.TotalVisibleMemorySize
        $freeKB  = [double]$os.FreePhysicalMemory
        if ($totalKB -gt 0) {
            $snap.MemPct     = [math]::Round((($totalKB - $freeKB) / $totalKB) * 100, 1)
            $snap.MemAvailMB = [math]::Round($freeKB / 1024, 0)
        }
    } catch { Write-Verbose "Memoire illisible : $_" }

    try {
        $disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk `
            -Filter "Name='_Total'" -ErrorAction Stop
        # PercentDiskTime peut depasser 100 sur plusieurs volumes : on plafonne.
        $snap.DiskPct   = [math]::Round([math]::Min([double]$disk.PercentDiskTime, 100), 1)
        $snap.DiskQueue = [double]$disk.CurrentDiskQueueLength
    } catch { Write-Verbose "Disque illisible : $_" }

    try {
        # PagesPerSec eleve = Windows swappe sur le disque : cause n1 des
        # ralentissements ressentis, meme quand le CPU a l'air calme.
        $mem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
        $snap.PagesPerSec = [math]::Round([double]$mem.PagesPerSec, 0)
    } catch { Write-Verbose "Compteurs memoire illisibles : $_" }

    try {
        $sys = Get-CimInstance Win32_LogicalDisk `
            -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction Stop
        $snap.FreeSpaceGB = [math]::Round([double]$sys.FreeSpace / 1GB, 1)
    } catch { Write-Verbose "Espace disque illisible : $_" }

    [pscustomobject]$snap
}

function Get-ProcessSnapshot {
    <#  Consommation par processus, regroupee par nom (chrome#1, chrome#2...
        comptent pour un seul "chrome" avec le total de ses instances).  #>
    try {
        $raw = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop |
            Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' }
    } catch {
        Write-Verbose "Liste des processus illisible : $_"
        return @()
    }

    $raw | Group-Object { ($_.Name -split '#')[0] } | ForEach-Object {
        $g = $_.Group
        [pscustomobject]@{
            Name      = $_.Name
            # PercentProcessorTime est cumule sur tous les coeurs : on ramene
            # a une echelle 0-100 comparable au CPU global.
            CpuPct    = [math]::Round((($g | Measure-Object PercentProcessorTime -Sum).Sum / $script:LogicalCores), 1)
            MemMB     = [math]::Round((($g | Measure-Object WorkingSetPrivate -Sum).Sum / 1MB), 0)
            IoMBPerS  = [math]::Round(((($g | Measure-Object IOReadBytesPerSec -Sum).Sum +
                                        ($g | Measure-Object IOWriteBytesPerSec -Sum).Sum) / 1MB), 1)
            Instances = $_.Count
        }
    }
}

function Format-Culprits {
    <#  Construit la ligne lisible "qui est responsable" d'une alerte.  #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Processes,
        [Parameter(Mandatory)][ValidateSet('CpuPct', 'MemMB', 'IoMBPerS')][string]$SortBy,
        [string]$Unit,
        [int]$Top = 3
    )

    if (-not $Processes -or $Processes.Count -eq 0) { return 'processus indisponibles' }

    $top = $Processes | Sort-Object -Property $SortBy -Descending | Select-Object -First $Top
    ($top | ForEach-Object {
        $label = $_.Name
        if ($script:KnownSystem.ContainsKey($_.Name)) {
            $label = "$($_.Name) [$($script:KnownSystem[$_.Name])]"
        }
        $inst = if ($_.Instances -gt 1) { " x$($_.Instances)" } else { '' }
        "$label$inst = $($_.$SortBy)$Unit"
    }) -join ' | '
}


# ---------------------------------------------------------------------------
# Journalisation
# ---------------------------------------------------------------------------

function Initialize-LogDirectory {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
}

function Get-LogPath {
    param([ValidateSet('metrics', 'alerts')][string]$Kind, [datetime]$Date = (Get-Date))
    Join-Path $LogDirectory ("{0}-{1:yyyy-MM-dd}.csv" -f $Kind, $Date)
}

function Remove-OldLogs {
    $cutoff = (Get-Date).AddDays(-$KeepDays)
    Get-ChildItem -LiteralPath $LogDirectory -Filter '*.csv' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

function Write-StatusLine {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] {1,-5} {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ALERTE' { Write-Host $line -ForegroundColor Yellow }
        'ERREUR' { Write-Host $line -ForegroundColor Red }
        default  { Write-Host $line }
    }
    Add-Content -LiteralPath (Join-Path $LogDirectory 'pcwatch.log') -Value $line -Encoding UTF8
}


# ---------------------------------------------------------------------------
# Boucle de surveillance
# ---------------------------------------------------------------------------

function Start-Monitoring {
    Initialize-LogDirectory
    Remove-OldLogs

    Write-StatusLine "Surveillance demarree - echantillon toutes les $IntervalSeconds s"
    Write-StatusLine "Seuils : CPU>$CpuThreshold% / RAM>$MemThreshold% / Disque>$DiskThreshold% pendant $SustainedSamples echantillons"
    Write-StatusLine "Journaux : $LogDirectory"
    Write-Host ''

    # Compteurs de persistance : une alerte n'est levee que si le seuil est
    # depasse sur $SustainedSamples echantillons d'affilee.
    $streak = @{ Cpu = 0; Mem = 0; Disk = 0 }
    # Empeche de re-alerter en boucle tant que la meme cause dure.
    $muted  = @{ Cpu = $false; Mem = $false; Disk = $false }
    $lastCleanup = Get-Date

    try {
        while ($true) {
            try {
                $sys = Get-SystemSnapshot
                Export-Csv -InputObject $sys -LiteralPath (Get-LogPath -Kind metrics) `
                    -Append -NoTypeInformation -Encoding UTF8

                # Les processus ne sont interroges que si un seuil est franchi :
                # inutile de payer ce cout a chaque echantillon quand tout va bien.
                $breaches = @()
                if ($null -ne $sys.CpuPct  -and $sys.CpuPct  -ge $CpuThreshold)  { $breaches += 'Cpu'  } else { $streak.Cpu  = 0; $muted.Cpu  = $false }
                if ($null -ne $sys.MemPct  -and $sys.MemPct  -ge $MemThreshold)  { $breaches += 'Mem'  } else { $streak.Mem  = 0; $muted.Mem  = $false }
                if ($null -ne $sys.DiskPct -and $sys.DiskPct -ge $DiskThreshold) { $breaches += 'Disk' } else { $streak.Disk = 0; $muted.Disk = $false }

                if ($breaches.Count -gt 0) {
                    $procs = @(Get-ProcessSnapshot)

                    foreach ($kind in $breaches) {
                        $streak[$kind]++
                        if ($streak[$kind] -lt $SustainedSamples -or $muted[$kind]) { continue }
                        $muted[$kind] = $true   # une alerte par episode, pas par echantillon

                        switch ($kind) {
                            'Cpu' {
                                $metric   = 'CPU'
                                $value    = $sys.CpuPct
                                $culprits = Format-Culprits -Processes $procs -SortBy CpuPct -Unit '%'
                                $detail   = "CPU a $($sys.CpuPct)%"
                            }
                            'Mem' {
                                $metric   = 'Memoire'
                                $value    = $sys.MemPct
                                $culprits = Format-Culprits -Processes $procs -SortBy MemMB -Unit ' Mo'
                                $swap     = if ($null -ne $sys.PagesPerSec -and $sys.PagesPerSec -gt 1000) { ' - SWAP INTENSIF (le PC pagine sur le disque)' } else { '' }
                                $detail   = "RAM a $($sys.MemPct)% ($($sys.MemAvailMB) Mo libres)$swap"
                            }
                            'Disk' {
                                $metric   = 'Disque'
                                $value    = $sys.DiskPct
                                $culprits = Format-Culprits -Processes $procs -SortBy IoMBPerS -Unit ' Mo/s'
                                $detail   = "Disque occupe a $($sys.DiskPct)% (file d'attente : $($sys.DiskQueue))"
                            }
                        }

                        $alert = [pscustomobject]@{
                            Timestamp = (Get-Date).ToString('s')
                            Metric    = $metric
                            Value     = $value
                            Detail    = $detail
                            Culprits  = $culprits
                        }
                        Export-Csv -InputObject $alert -LiteralPath (Get-LogPath -Kind alerts) `
                            -Append -NoTypeInformation -Encoding UTF8

                        Write-StatusLine "$detail -> $culprits" 'ALERTE'
                    }
                }

                # Purge quotidienne des vieux journaux.
                if (((Get-Date) - $lastCleanup).TotalHours -ge 24) {
                    Remove-OldLogs
                    $lastCleanup = Get-Date
                }
            }
            catch {
                # Un echantillon rate ne doit jamais tuer la surveillance.
                Write-StatusLine "Echantillon ignore : $($_.Exception.Message)" 'ERREUR'
            }

            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    finally {
        Write-StatusLine 'Surveillance arretee.'
    }
}


# ---------------------------------------------------------------------------
# Bilan
# ---------------------------------------------------------------------------

function Get-Percentile {
    param([double[]]$Values, [double]$Percentile)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    $index  = [math]::Ceiling(($Percentile / 100) * $sorted.Count) - 1
    $sorted[[math]::Max(0, [math]::Min($index, $sorted.Count - 1))]
}

function Show-Report {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        Write-Host "Aucun journal trouve dans $LogDirectory. Lance d'abord la surveillance." -ForegroundColor Yellow
        return
    }

    $since = (Get-Date).AddDays(-$ReportDays)

    $metrics = @(
        Get-ChildItem -LiteralPath $LogDirectory -Filter 'metrics-*.csv' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $since } |
            ForEach-Object { Import-Csv -LiteralPath $_.FullName }
    )
    $alerts = @(
        Get-ChildItem -LiteralPath $LogDirectory -Filter 'alerts-*.csv' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $since } |
            ForEach-Object { Import-Csv -LiteralPath $_.FullName }
    )

    Write-Host ''
    Write-Host "===== BILAN PCWatch - $ReportDays derniers jours =====" -ForegroundColor Cyan
    Write-Host ''

    if ($metrics.Count -eq 0) {
        Write-Host 'Aucune mesure sur la periode.' -ForegroundColor Yellow
        return
    }

    Write-Host "Echantillons analyses : $($metrics.Count)"
    Write-Host ''

    foreach ($m in @(
        @{ Label = 'CPU'          ; Field = 'CpuPct'  ; Unit = '%' }
        @{ Label = 'Memoire'      ; Field = 'MemPct'  ; Unit = '%' }
        @{ Label = 'Charge disque'; Field = 'DiskPct' ; Unit = '%' }
    )) {
        $vals = @($metrics | ForEach-Object { $_.($m.Field) } |
                  Where-Object { $_ -ne '' -and $null -ne $_ } |
                  ForEach-Object { [double]$_ })
        if ($vals.Count -eq 0) { continue }
        $med = Get-Percentile -Values $vals -Percentile 50
        $p95 = Get-Percentile -Values $vals -Percentile 95
        $max = ($vals | Measure-Object -Maximum).Maximum
        Write-Host ("{0,-14} median {1,6}{4}   p95 {2,6}{4}   max {3,6}{4}" -f $m.Label, $med, $p95, $max, $m.Unit)
    }

    # Espace disque : une partition systeme presque pleine ralentit tout.
    $freeVals = @($metrics | ForEach-Object { $_.FreeSpaceGB } |
                  Where-Object { $_ -ne '' -and $null -ne $_ } |
                  ForEach-Object { [double]$_ })
    if ($freeVals.Count -gt 0) {
        $lastFree = $freeVals[-1]
        Write-Host ("{0,-14} {1} Go libres sur {2}" -f 'Espace disque', $lastFree, $env:SystemDrive)
        if ($lastFree -lt 20) {
            Write-Host '   /!\ Moins de 20 Go libres : Windows ralentit nettement en dessous de ce seuil.' -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host "----- Ralentissements detectes : $($alerts.Count) -----" -ForegroundColor Cyan

    if ($alerts.Count -eq 0) {
        Write-Host 'Aucun. Le PC est reste sous les seuils sur toute la periode.' -ForegroundColor Green
        Write-Host ''
        return
    }

    Write-Host ''
    Write-Host 'Par type :'
    $alerts | Group-Object Metric | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,-10} {1} episode(s)" -f $_.Name, $_.Count)
    }

    Write-Host ''
    Write-Host 'Processus les plus souvent en tete lors des ralentissements :'
    $alerts |
        ForEach-Object { ($_.Culprits -split '\|')[0].Trim() } |
        ForEach-Object { ($_ -split '\s*[\[=]')[0].Trim() } |
        Where-Object { $_ } |
        Group-Object | Sort-Object Count -Descending | Select-Object -First 8 |
        ForEach-Object {
            $note = if ($script:KnownSystem.ContainsKey($_.Name)) { "  <- $($script:KnownSystem[$_.Name])" } else { '' }
            Write-Host ("  {0,-24} {1,3} fois{2}" -f $_.Name, $_.Count, $note)
        }

    Write-Host ''
    Write-Host 'Heures de la journee les plus touchees :'
    $alerts |
        Group-Object { '{0:00}h' -f ([datetime]$_.Timestamp).Hour } |
        Sort-Object Count -Descending | Select-Object -First 5 |
        ForEach-Object { Write-Host ("  {0}  {1} episode(s)" -f $_.Name, $_.Count) }

    Write-Host ''
    Write-Host '5 derniers episodes :'
    $alerts | Select-Object -Last 5 | ForEach-Object {
        Write-Host ("  {0}  {1}" -f ([datetime]$_.Timestamp).ToString('dd/MM HH:mm'), $_.Detail) -ForegroundColor Yellow
        Write-Host ("      {0}" -f $_.Culprits) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host "Journaux complets : $LogDirectory"
    Write-Host ''
}


# ---------------------------------------------------------------------------
# Installation / desinstallation (tache planifiee, sans droits admin)
# ---------------------------------------------------------------------------

function Install-Monitor {
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        throw "Impossible de determiner le chemin du script. Lance-le depuis son fichier .ps1."
    }

    $arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" +
                 " -IntervalSeconds $IntervalSeconds -CpuThreshold $CpuThreshold" +
                 " -MemThreshold $MemThreshold -DiskThreshold $DiskThreshold" +
                 " -SustainedSamples $SustainedSamples -KeepDays $KeepDays"

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # ExecutionTimeLimit a 0 = pas de limite : la tache doit tourner en continu.
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -MultipleInstances IgnoreNew

    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Description 'Surveillance continue des performances (PCWatch)' | Out-Null

    Start-ScheduledTask -TaskName $script:TaskName

    Write-Host ''
    Write-Host 'PCWatch est installe et demarre.' -ForegroundColor Green
    Write-Host "  Il redemarrera automatiquement a chaque ouverture de session."
    Write-Host "  Journaux    : $LogDirectory"
    Write-Host "  Voir le bilan : .\PCWatch.ps1 -Report"
    Write-Host "  Desinstaller  : .\PCWatch.ps1 -Uninstall"
    Write-Host ''
}

function Uninstall-Monitor {
    $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host 'PCWatch n''est pas installe.' -ForegroundColor Yellow
        return
    }
    Stop-ScheduledTask  -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
    Write-Host 'PCWatch desinstalle. Les journaux sont conserves dans :' -ForegroundColor Green
    Write-Host "  $LogDirectory"
}


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------

switch ($PSCmdlet.ParameterSetName) {
    'Install'   { Install-Monitor }
    'Uninstall' { Uninstall-Monitor }
    'Report'    { Show-Report }
    default     { Start-Monitoring }
}
