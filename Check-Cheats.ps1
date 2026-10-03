# ==============================================================================
# MINECRAFT FORENSIC AUDIT & PC-CHECK TOOL v6.0 (ALL-IN-ONE CONSOLE EDITION)
# Скрипт глубокого криминалистического анализа ПК для модераторов серверов Minecraft.
# Предназначен для прямого запуска через консоль или из сети (GitHub Web One-Liner).
# ==============================================================================

[CmdletBinding()]
param(
    [int]$Days = 14
)

# ------------------------------------------------------------------------------
# 0. Проверка привилегий Администратора
# ------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n [!] ОШИБКА: Требуются права Администратора!" -ForegroundColor Red
    Write-Host "     Для сканирования кэшей ядра (ShimCache, BAM), системных журналов и VSS" -ForegroundColor Yellow
    Write-Host "     необходимо запустить PowerShell от имени Администратора.`n" -ForegroundColor Yellow
    return
}

# ------------------------------------------------------------------------------
# 1. Сигнатуры и коллекции
# ------------------------------------------------------------------------------
$CutoffDate = (Get-Date).AddDays(-$Days)
$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$CleaningEvidence = [System.Collections.Generic.List[PSCustomObject]]::new()

$CheatKeywords = @(
    "wildclient", "wild-loader", "bellum", "kalimod", "kaliclient", "celestial", "enigma-tech", "enigma",
    "grimoiredlc", "grimoire", "wyvern", "wyvern-dlc", "exloader", "exocracked", "exodium", "deltaclient", "delta-client",
    "neverlose", "phobia", "nursultan", "expensive", "minced", "doomsday", "thunderhack", "liquidbounce", "wurst",
    "meteor", "bleachhack", "aristois", "impact", "sigma", "future", "rusherhack", "inertia", "akrien", "expensive-client",
    "combat-hitbox", "hitbox", "clickpearl", "neuropasta", "hud_eva", "darnixx", "freelook", "gamma-utils",
    "netprodis", "lag machine", "basefinder", "autocfg", "autobuy", "kulhvh", "donk rage", "ip spoofer", "ip_changer",
    "fantazy", "cooldownswidget", "keybindswidget", "simpleminecraftddos", "op auto clicker", "autoclicker",
    "reach", "killaura", "aimbot", "velocity", "antiknockback", "fastplace", "scaffold", "autoarmor",
    "autopot", "tg-tunnel", "tg_ws_proxy", "tgwsproxy"
)

$CleanerKeywords = @(
    "journaltrace", "shellbag_analyzer", "shellbag", "bleachbit", "privazer", "ccleaner", "usn wiper",
    "deletejournal", "delete_journal", "cleaner", "wiper", "everything -reindex", "wevtutil cl"
)

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity, # CRITICAL, HIGH, SUSPICIOUS, MEDIUM
        [string]$Artifact,
        [string]$Details,
        [datetime]$Timestamp = [DateTime]::MinValue
    )
    $obj = [PSCustomObject]@{
        Time       = if ($Timestamp -ne [DateTime]::MinValue) { $Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "Н/Д" }
        RawTime    = $Timestamp
        Severity   = $Severity
        Category   = $Category
        Artifact   = $Artifact
        Details    = $Details
    }
    $Findings.Add($obj)
}

function Add-CleaningAlert {
    param(
        [string]$Type,
        [string]$Indicator,
        [string]$Description
    )
    $obj = [PSCustomObject]@{
        Type        = $Type
        Indicator   = $Indicator
        Description = $Description
    }
    $CleaningEvidence.Add($obj)
}

# ------------------------------------------------------------------------------
# Консольный стартовый заголовок
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "       MINECRAFT FORENSIC AUDIT & PC-CHECK TOOL v6.0 (CONSOLE EDITION)          " -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Хост: $env:COMPUTERNAME | Пользователь: $env:USERNAME" -ForegroundColor Gray
Write-Host " Анализируемый период: последние $Days дней (с $($CutoffDate.ToString('dd.MM.yyyy HH:mm')))" -ForegroundColor Gray
Write-Host " Запуск глубокого сканирования 12 уровней системы... Пожалуйста, подождите." -ForegroundColor DarkGray
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

# ==============================================================================
# МОДУЛЬ 1: АНАЛИЗ ПОПЫТОК ОЧИСТКИ (ANTI-FORENSICS & WIPERS)
# ==============================================================================
Write-Host "[1/12] Проверка анти-форензики и следов чистки системы..." -ForegroundColor Yellow

# 1.1 USN Journal
try {
    $usnOut = & fsutil usn queryjournal C: 2>&1 | Out-String
    $nextUsnMatch = [regex]::Match($usnOut, "(?:Следующий USN|Next USN)\s*:\s*0x([0-9a-fA-F]+)", "IgnoreCase")
    if ($nextUsnMatch.Success) {
        $nextUsnVal = [Convert]::ToInt64($nextUsnMatch.Groups[1].Value, 16)
        if ($nextUsnVal -lt 0x1000000) {
            Add-CleaningAlert -Type "Сброс NTFS USN Journal ($UsnJrnl)" `
                -Indicator "Next USN: 0x$($nextUsnMatch.Groups[1].Value) (~$([math]::Round($nextUsnVal/1MB, 2)) MB)" `
                -Description "Журнал изменений NTFS тома C: был сброшен (fsutil usn deletejournal). Вся история создания и удаления файлов уничтожена!"
        }
    }
} catch {}

# 1.2 ShellBags
try {
    $bagMru = Get-ChildItem "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" -Recurse -ErrorAction SilentlyContinue
    $count = if ($bagMru) { $bagMru.Count } else { 0 }
    if ($count -lt 15) {
        Add-CleaningAlert -Type "Очистка веток реестра ShellBags" `
            -Indicator "Количество сохраненных папок BagMRU: $count (норма > 50-100)" `
            -Description "История открытия папок в Проводнике была принудительно стерта специализированным клинером."
    }
} catch {}

# 1.3 Prefetch клинеров
try {
    $pfFiles = Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    $pfCleaners = $pfFiles | Where-Object { $_.Name -match "FSUTIL|WEVTUTIL|JOURNALTRACE|SHELLBAG|EVERYTHING" }
    foreach ($c in $pfCleaners) {
        if ($c.LastWriteTime -ge $CutoffDate) {
            Add-Finding -Category "Anti-Forensics" -Severity "HIGH" -Artifact $c.Name `
                -Details "Запуск утилиты манипуляции журналами / принудительной переиндексации" `
                -Timestamp $c.LastWriteTime
        }
    }
} catch {}

# 1.4 PSReadLine history
try {
    $psHistoryPath = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $psHistoryPath) {
        $historyLines = Get-Content $psHistoryPath -ErrorAction SilentlyContinue
        $suspiciousCommands = $historyLines | Where-Object { 
            $_ -match "deletejournal|usn|wevtutil|irm.*iex|Invoke-Expression|Remove-Item.*\.gemini|Stop-Process.*explorer|fsutil" 
        }
        foreach ($cmd in $suspiciousCommands) {
            Add-Finding -Category "Anti-Forensics" -Severity "SUSPICIOUS" -Artifact "История PowerShell" `
                -Details "Подозрительная команда в консоли: $cmd"
        }
    }
} catch {}

# 1.5 Recycle Bin
try {
    $recycleBins = Get-ChildItem -Path "C:\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -match "S-1-5-21-" }
    foreach ($rb in $recycleBins) {
        if ($rb.LastWriteTime -ge $CutoffDate) {
            Add-Finding -Category "RecycleBin" -Severity "MEDIUM" -Artifact $rb.Name `
                -Details "Корзина пользователя была очищена или изменена в этот момент" `
                -Timestamp $rb.LastWriteTime
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 2: SHIMCACHE (APPCOMPATCACHE)
# ==============================================================================
Write-Host "[2/12] Извлечение записей из ShimCache ядра Windows..." -ForegroundColor Yellow

try {
    $shimReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -ErrorAction Stop
    $shimBytes = $shimReg.AppCompatCache
    if ($shimBytes) {
        $shimStr = [System.Text.Encoding]::Unicode.GetString($shimBytes)
        $pathRegex = [regex]'(?:[a-zA-Z]\:|\\\\\?\\)[^\x00-\x1F\"\<\>\*\?\|]+\.(?:exe|dll|bat|cmd|jar)'
        $extractedPaths = $pathRegex.Matches($shimStr) | ForEach-Object { $_.Value } | Select-Object -Unique
        
        foreach ($exePath in $extractedPaths) {
            $isCheat = $false
            foreach ($kw in $CheatKeywords) {
                if ($exePath -match [regex]::Escape($kw)) {
                    $isCheat = $true
                    break
                }
            }
            if ($isCheat) {
                Add-Finding -Category "ShimCache" -Severity "CRITICAL" -Artifact $exePath `
                    -Details "Запуск чит-файла сохранен в системном кэше совместимости AppCompatCache"
            }
            foreach ($ckw in $CleanerKeywords) {
                if ($exePath -match [regex]::Escape($ckw)) {
                    Add-Finding -Category "ShimCache" -Severity "HIGH" -Artifact $exePath `
                        -Details "Запуск клинера/утилиты удаления следов зафиксирован в AppCompatCache"
                    break
                }
            }
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 3: PROGRAM COMPATIBILITY ASSISTANT (PCA)
# ==============================================================================
Write-Host "[3/12] Проверка баз Program Compatibility Assistant (PCA)..." -ForegroundColor Yellow

# 3.1 PcaAppLaunchDic
$pcaDicPath = "C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"
if (Test-Path $pcaDicPath) {
    try {
        $pcaDicLines = Get-Content $pcaDicPath -ErrorAction SilentlyContinue
        foreach ($line in $pcaDicLines) {
            if ($line.Contains("|")) {
                $parts = $line.Split('|')
                $path = $parts[0]
                $timeStr = $parts[1]
                $dt = [DateTime]::MinValue
                [DateTime]::TryParse($timeStr, [ref]$dt) | Out-Null
                
                if ($dt -ge $CutoffDate -or $dt -eq [DateTime]::MinValue) {
                    foreach ($kw in $CheatKeywords) {
                        if ($path -match [regex]::Escape($kw)) {
                            Add-Finding -Category "PCA-Launch" -Severity "CRITICAL" -Artifact $path `
                                -Details "Запуск сохранен в словаре совместимости PCA" -Timestamp $dt
                            break
                        }
                    }
                    foreach ($ckw in $CleanerKeywords) {
                        if ($path -match [regex]::Escape($ckw)) {
                            Add-Finding -Category "PCA-Launch" -Severity "HIGH" -Artifact $path `
                                -Details "Запуск клинера зафиксирован в словаре PCA" -Timestamp $dt
                            break
                        }
                    }
                }
            }
        }
    } catch {}
}

# 3.2 PcaGeneralDb
@("C:\Windows\appcompat\pca\PcaGeneralDb0.txt", "C:\Windows\appcompat\pca\PcaGeneralDb1.txt") | ForEach-Object {
    if (Test-Path $_) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($_)
            $text = [System.Text.Encoding]::Unicode.GetString($bytes)
            $lines = $text -split "`r`n"
            foreach ($line in $lines) {
                if ($line.Contains("|")) {
                    $parts = $line.Split('|')
                    $timeStr = $parts[0]
                    $path = if ($parts.Length -gt 2) { $parts[2] } else { "" }
                    $exitCode = if ($parts.Length -gt 7) { $parts[7] } else { "" }
                    $dt = [DateTime]::MinValue
                    [DateTime]::TryParse($timeStr, [ref]$dt) | Out-Null
                    
                    if ($dt -ge $CutoffDate -or $dt -eq [DateTime]::MinValue) {
                        foreach ($kw in $CheatKeywords) {
                            if ($path -match [regex]::Escape($kw) -or $line -match [regex]::Escape($kw)) {
                                Add-Finding -Category "PCA-Db" -Severity "CRITICAL" -Artifact $path `
                                    -Details "Запуск/сбой чит-процесса зафиксирован в журнале PCA! Код выхода: $exitCode" -Timestamp $dt
                                break
                            }
                        }
                    }
                }
            }
        } catch {}
    }
}

# ==============================================================================
# МОДУЛЬ 4: MUICACHE, FEATUREUSAGE И ИСТОРИЯ ПРОВОДНИКА
# ==============================================================================
Write-Host "[4/12] Сканирование MuiCache, переключений окон и истории путей..." -ForegroundColor Yellow

# 4.1 MuiCache
try {
    $mui = Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" -ErrorAction SilentlyContinue
    if ($mui) {
        foreach ($prop in $mui.PSObject.Properties) {
            $name = $prop.Name
            foreach ($kw in $CheatKeywords) {
                if ($name -match [regex]::Escape($kw)) {
                    Add-Finding -Category "MuiCache" -Severity "CRITICAL" -Artifact $name `
                        -Details "В кэше MuiCache сохранились данные чит-файла! Имя в GUI: $($prop.Value)"
                    break
                }
            }
            foreach ($ckw in $CleanerKeywords) {
                if ($name -match [regex]::Escape($ckw)) {
                    Add-Finding -Category "MuiCache" -Severity "HIGH" -Artifact $name `
                        -Details "В MuiCache обнаружена утилита очистки: $($prop.Value)"
                    break
                }
            }
        }
    }
} catch {}

# 4.2 FeatureUsage
try {
    $appSwitched = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" -ErrorAction SilentlyContinue
    if ($appSwitched) {
        foreach ($prop in $appSwitched.PSObject.Properties) {
            $name = $prop.Name
            $val = $prop.Value
            foreach ($kw in $CheatKeywords) {
                if ($name -match [regex]::Escape($kw)) {
                    Add-Finding -Category "FeatureUsage" -Severity "CRITICAL" -Artifact $name `
                        -Details "Зафиксировано активных переключений на окно приложения: $val раз!"
                    break
                }
            }
        }
    }
} catch {}

# 4.3 TypedPaths
try {
    $typedPaths = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -ErrorAction SilentlyContinue
    if ($typedPaths) {
        foreach ($prop in $typedPaths.PSObject.Properties) {
            $val = "$($prop.Value)"
            foreach ($kw in $CheatKeywords + $CleanerKeywords) {
                if ($val -match [regex]::Escape($kw)) {
                    Add-Finding -Category "TypedPaths" -Severity "HIGH" -Artifact $val `
                        -Details "Путь вводился вручную в адресную строку Проводника"
                    break
                }
            }
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 5: CONSENTSTORE (ДОСТУП К АУДИО / МИКРОФОНУ)
# ==============================================================================
Write-Host "[5/12] Анализ ConsentStore (захват аудио и устройств читами)..." -ForegroundColor Yellow

try {
    $consentPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    $micItems = Get-ChildItem -Path "$consentPath\microphone\NonPackaged" -ErrorAction SilentlyContinue
    foreach ($item in $micItems) {
        $realPath = $item.PSChildName -replace "#", "\"
        $prop = Get-ItemProperty -Path $item.PSPath
        $timeStop = $prop.LastUsedTimeStop
        $dt = [DateTime]::MinValue
        if ($timeStop -gt 0) {
            try { $dt = [DateTime]::FromFileTime($timeStop) } catch {}
        }
        foreach ($kw in $CheatKeywords) {
            if ($realPath -match [regex]::Escape($kw)) {
                Add-Finding -Category "ConsentStore" -Severity "CRITICAL" -Artifact $realPath `
                    -Details "Чит-клиент/лаунчер использовал аудио-устройства системы (voicechat/звуковые хуки)" `
                    -Timestamp $dt
                break
            }
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 6: CRASHDUMPS И СОБЫТИЯ СБОЕВ (EVENT ID 1000)
# ==============================================================================
Write-Host "[6/12] Поиск дампов памяти CrashDumps и журналов сбоев..." -ForegroundColor Yellow

try {
    $dumpFiles = Get-ChildItem -Path "$env:LOCALAPPDATA\CrashDumps" -Filter "*.dmp" -ErrorAction SilentlyContinue
    foreach ($df in $dumpFiles) {
        if ($df.LastWriteTime -ge $CutoffDate) {
            foreach ($kw in $CheatKeywords + @("javaw")) {
                if ($df.Name -match [regex]::Escape($kw)) {
                    $sev = if ($df.Name -match "javaw") { "SUSPICIOUS" } else { "CRITICAL" }
                    Add-Finding -Category "CrashDump" -Severity $sev -Artifact $df.FullName `
                        -Details "Обнаружен сохраненный полный аварийный дамп памяти упавшего процесса ($([math]::Round($df.Length/1MB, 2)) MB)" `
                        -Timestamp $df.LastWriteTime
                    break
                }
            }
        }
    }
} catch {}

try {
    $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$CutoffDate; Id=1000} -ErrorAction SilentlyContinue
    foreach ($ev in $appEvents) {
        $msg = $ev.Message
        foreach ($kw in $CheatKeywords) {
            if ($msg -match [regex]::Escape($kw)) {
                $faultApp = [regex]::Match($msg, "(?:Имя сбойного приложения|Faulting application name):\s*([^\r\n,]+)").Groups[1].Value.Trim()
                Add-Finding -Category "EventLog-AppCrash" -Severity "CRITICAL" -Artifact "Событие Application 1000" `
                    -Details "Зафиксирован краш чит-процесса: $faultApp" `
                    -Timestamp $ev.TimeCreated
                break
            }
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 7: BAM (BACKGROUND ACTIVITY MODERATOR)
# ==============================================================================
Write-Host "[7/12] Анализ времени запуска процессов в реестре BAM..." -ForegroundColor Yellow

try {
    $bamUserKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" -ErrorAction SilentlyContinue
    foreach ($uKey in $bamUserKeys) {
        $props = Get-ItemProperty -Path $uKey.PSPath
        foreach ($prop in $props.PSObject.Properties) {
            $name = $prop.Name
            $val = $prop.Value
            if ($val -is [byte[]] -and $val.Length -ge 8) {
                $ft = [BitConverter]::ToInt64($val, 0)
                $dt = [DateTime]::MinValue
                try { $dt = [DateTime]::FromFileTime($ft) } catch {}
                
                if ($dt -ge $CutoffDate) {
                    foreach ($kw in $CheatKeywords) {
                        if ($name -match [regex]::Escape($kw)) {
                            Add-Finding -Category "BAM" -Severity "CRITICAL" -Artifact $name `
                                -Details "Точное время активности процесса зафиксировано ядром в BAM" `
                                -Timestamp $dt
                            break
                        }
                    }
                    foreach ($ckw in $CleanerKeywords) {
                        if ($name -match [regex]::Escape($ckw)) {
                            Add-Finding -Category "BAM" -Severity "HIGH" -Artifact $name `
                                -Details "Запуск клинера/утилиты удаления следов зафиксирован в BAM" `
                                -Timestamp $dt
                            break
                        }
                    }
                }
            }
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 8: УСТАНОВКА СЛУЖБ И ДРАЙВЕРОВ (EVENT ID 7045)
# ==============================================================================
Write-Host "[8/12] Проверка установки драйверов фильтрации и хуков (Event 7045)..." -ForegroundColor Yellow

try {
    $serviceEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$CutoffDate; Id=7045} -ErrorAction SilentlyContinue
    foreach ($sev in $serviceEvents) {
        $svcName = "$($sev.Properties[0].Value)"
        $imgPath = "$($sev.Properties[1].Value)"
        
        if ($svcName -match "WinDivert|FvKMDSvc|ProcessHacker|Capcom|GIO|KProcessHacker") {
            Add-Finding -Category "KernelDriver" -Severity "HIGH" -Artifact "Служба: $svcName" `
                -Details "Установка драйвера перехвата пакетов/памяти: $imgPath" `
                -Timestamp $sev.TimeCreated
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 9: АНАЛИЗ ДИРЕКТОРИЙ MINECRAFT, КОНФИГОВ И КРАШ-ЛОГОВ
# ==============================================================================
Write-Host "[9/12] Поиск зацепок в профилях Minecraft и crash-reports..." -ForegroundColor Yellow

$mcPaths = @(
    "$env:APPDATA\.minecraft",
    "$env:APPDATA\.tlauncher\legacy\Minecraft\game",
    "$env:APPDATA\.tlauncher\Minecraft",
    "$env:APPDATA\LabyMod",
    "$env:APPDATA\lunarclient",
    "$env:USERPROFILE\.pulse"
)

foreach ($mcBase in $mcPaths) {
    if (Test-Path $mcBase) {
        # Папки читов
        $cheatDirs = Get-ChildItem -Path $mcBase -Directory -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -match "Celestial|Grimoire|Phobia|baritone|Kali|Wild|Meteor|Wurst" 
        }
        foreach ($cd in $cheatDirs) {
            Add-Finding -Category "Minecraft-ConfigFolder" -Severity "CRITICAL" -Artifact $cd.FullName `
                -Details "Обнаружена активная директория конфигураций и данных чита!" `
                -Timestamp $cd.LastWriteTime
        }
        
        # Остаточные файлы
        $suspiciousFiles = Get-ChildItem -Path $mcBase -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "basefinder|celka|grimoire|friends\.json|staffName\.json"
        }
        foreach ($sf in $suspiciousFiles) {
            Add-Finding -Category "Minecraft-Artifact" -Severity "HIGH" -Artifact $sf.FullName `
                -Details "Файл артефакта чита ($($sf.Name)) сохранился в папке игры" `
                -Timestamp $sf.LastWriteTime
        }
        
        # Краш-репорты
        $crashDir = Join-Path $mcBase "crash-reports"
        if (Test-Path $crashDir) {
            $crashes = Get-ChildItem -Path $crashDir -Filter "crash-*.txt" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $CutoffDate }
            foreach ($cr in $crashes) {
                try {
                    $content = Get-Content $cr.FullName -TotalCount 70 -ErrorAction SilentlyContinue
                    $matchLine = $content | Where-Object { $_ -match "wtf\.wyvern|grimoire|celestial|kalimod|kaliclient|net\.minecraft\.class_" } | Select-Object -First 1
                    if ($matchLine) {
                        Add-Finding -Category "Minecraft-CrashReport" -Severity "CRITICAL" -Artifact $cr.FullName `
                            -Details "В стектрейсе краша обнаружены классы чит-клиента: $($matchLine.Trim())" `
                            -Timestamp $cr.LastWriteTime
                    }
                } catch {}
            }
        }
        
        # Выкрученная гамма
        $optionsFile = Join-Path $mcBase "options.txt"
        if (Test-Path $optionsFile) {
            try {
                $gammaLine = Get-Content $optionsFile -ErrorAction SilentlyContinue | Where-Object { $_ -match "^gamma:" } | Select-Object -First 1
                if ($gammaLine) {
                    $gammaVal = [double]($gammaLine -replace "gamma:", "").Trim()
                    if ($gammaVal -gt 5.0) {
                        Add-Finding -Category "Minecraft-Options" -Severity "MEDIUM" -Artifact $optionsFile `
                            -Details "Обнаружена выкрученная читерская гамма (FullBright): gamma=$gammaVal (норма <= 1.0)"
                    }
                }
            } catch {}
        }
    }
}

# ==============================================================================
# МОДУЛЬ 10: ТЕНЕВЫЕ КОПИИ ТОМА (VSS - VOLUME SHADOW COPIES)
# ==============================================================================
Write-Host "[10/12] Инспекция теневых копий тома (VSS) на удаленные файлы..." -ForegroundColor Yellow

try {
    $vssOut = & vssadmin list shadows 2>&1 | Out-String
    $shadowPaths = [regex]::Matches($vssOut, '\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+') | ForEach-Object { $_.Value } | Select-Object -Unique
    if ($shadowPaths) {
        $latestShadow = $shadowPaths[-1]
        $tempSymlink = "$env:TEMP\VssInspect_$(Get-Random)"
        try {
            & cmd.exe /c "mklink /d `"$tempSymlink`" `"$latestShadow\`"" | Out-Null
            if (Test-Path $tempSymlink) {
                $vssSuspectPaths = @(
                    "$tempSymlink\Users\$env:USERNAME\Desktop\GrimoireDLC",
                    "$tempSymlink\Users\$env:USERNAME\Desktop\KaliMod",
                    "$tempSymlink\Users\$env:USERNAME\Desktop\Наработки",
                    "$tempSymlink\Users\$env:USERNAME\Desktop\WILDCLIENT (2).exe",
                    "$tempSymlink\WildClient",
                    "$tempSymlink\Kali",
                    "$tempSymlink\Celestial",
                    "$tempSymlink\enigma-tech",
                    "$tempSymlink\Program Files\WILD"
                )
                foreach ($sp in $vssSuspectPaths) {
                    if (Test-Path $sp) {
                        $cleanName = $sp -replace [regex]::Escape($tempSymlink), "C:"
                        Add-Finding -Category "VSS-ShadowCopy" -Severity "CRITICAL" -Artifact "Теневая копия ($cleanName)" `
                            -Details "ФАЙЛ/ПАПКА, УДАЛЕННАЯ С ДИСКА, ПОЛНОСТЬЮ СОХРАНИЛАСЬ В ТЕНЕВОЙ КОПИИ ТОМА!"
                    }
                }
            }
        } finally {
            if (Test-Path $tempSymlink) {
                & cmd.exe /c "rmdir `"$tempSymlink`"" | Out-Null
            }
        }
    }
} catch {}

# ==============================================================================
# МОДУЛЬ 11: ФАЙЛОВАЯ СИСТЕМА ЗА 14 ДНЕЙ
# ==============================================================================
Write-Host "[11/12] Сканирование пользовательских папок на остаточные файлы..." -ForegroundColor Yellow

$fsTargets = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:LOCALAPPDATA\Temp",
    "$env:APPDATA\com.swiftsoft",
    "$env:LOCALAPPDATA\KaliMod",
    "$env:LOCALAPPDATA\Bellum",
    "$env:LOCALAPPDATA\ExoCracked"
)

foreach ($targetDir in $fsTargets) {
    if (Test-Path $targetDir) {
        $recentFiles = Get-ChildItem -Path $targetDir -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            -not $_.PSIsContainer -and $_.LastWriteTime -ge $CutoffDate
        }
        foreach ($rf in $recentFiles) {
            foreach ($kw in $CheatKeywords) {
                if ($rf.Name -match [regex]::Escape($kw)) {
                    Add-Finding -Category "FileSystem" -Severity "CRITICAL" -Artifact $rf.FullName `
                        -Details "Файл чита/скрипта изменен в течение последних $Days дней ($([math]::Round($rf.Length/1KB, 1)) KB)" `
                        -Timestamp $rf.LastWriteTime
                    break
                }
            }
        }
    }
}

# ==============================================================================
# МОДУЛЬ 12: АКТИВНЫЕ ПРОЦЕССЫ И JVM-АРГУМЕНТЫ
# ==============================================================================
Write-Host "[12/12] Инспекция запущенных процессов и аргументов Java..." -ForegroundColor Yellow

try {
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($proc in $processes) {
        $cmdLine = "$($proc.CommandLine)"
        $pName = "$($proc.Name)"
        if ($pName -match "javaw|java") {
            if ($cmdLine -match "-javaagent:|fabric|forge|wyvern|grimoire|celestial|kali") {
                foreach ($kw in $CheatKeywords) {
                    if ($cmdLine -match [regex]::Escape($kw)) {
                        Add-Finding -Category "ActiveMemory" -Severity "CRITICAL" -Artifact "Процесс $pName (PID: $($proc.ProcessId))" `
                            -Details "В аргументах запущенной Java обнаружен чит-модуль/агент: $cmdLine"
                        break
                    }
                }
            }
        }
    }
} catch {}

# ==============================================================================
# ОБОБЩЕННЫЙ РЕЗУЛЬТАТ В КОНСОЛИ
# ==============================================================================
$criticalFindings = $Findings | Where-Object { $_.Severity -eq "CRITICAL" }
$highFindings     = $Findings | Where-Object { $_.Severity -eq "HIGH" }
$suspiciousItems  = $Findings | Where-Object { $_.Severity -in @("SUSPICIOUS", "MEDIUM") }

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                    ОБОБЩЕННЫЕ РЕЗУЛЬТАТЫ ПРОВЕРКИ                              " -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Cyan

# БАННЕР ВЕРДИКТА
if ($criticalFindings.Count -gt 0) {
    Write-Host "`n  #####################################################################" -ForegroundColor Red
    Write-Host "  [!!!] ВЕРДИКТ: ЧИТЫ ОБНАРУЖЕНЫ (CHEATS DETECTED) [!!!]" -ForegroundColor White -BackgroundColor DarkRed
    Write-Host "  #####################################################################`n" -ForegroundColor Red
} elseif ($CleaningEvidence.Count -gt 0) {
    Write-Host "`n  #####################################################################" -ForegroundColor Magenta
    Write-Host "  [!] ВЕРДИКТ: ОБНАРУЖЕНА НАМЕРЕННАЯ ОЧИСТКА ПК (ANTI-FORENSICS / WIPING) [!]" -ForegroundColor White -BackgroundColor DarkMagenta
    Write-Host "  #####################################################################`n" -ForegroundColor Magenta
} else {
    Write-Host "`n  #####################################################################" -ForegroundColor Green
    Write-Host "  [OK] ВЕРДИКТ: ЧИСТО (Прямых следов читов за $Days дней не найдено)" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "  #####################################################################`n" -ForegroundColor Green
}

# СВОДНАЯ СТАТИСТИКА
Write-Host "  [+] Сводка по категориям обнаружений:" -ForegroundColor Cyan
Write-Host "      * Прямые улики и запуски читов (CRITICAL) : $($criticalFindings.Count)" -ForegroundColor $(if ($criticalFindings.Count -gt 0) { "Red" } else { "Green" })
Write-Host "      * Сопутствующие драйверы / клинеры (HIGH) : $($highFindings.Count)" -ForegroundColor $(if ($highFindings.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "      * Подозрительные активности / следы       : $($suspiciousItems.Count)" -ForegroundColor Gray
Write-Host "      * Доказательства попыток очистки ПК       : $($CleaningEvidence.Count)" -ForegroundColor $(if ($CleaningEvidence.Count -gt 0) { "Magenta" } else { "Green" })

# ТАБЛИЦА СЛЕДОВ ОЧИСТКИ
if ($CleaningEvidence.Count -gt 0) {
    Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkMagenta
    Write-Host " [!] СЛЕДЫ ИСПОЛЬЗОВАНИЯ ВАЙПЕРОВ И ОЧИСТКИ СИСТЕМЫ:" -ForegroundColor Magenta
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkMagenta
    foreach ($ce in $CleaningEvidence) {
        Write-Host "  * Тип: $($ce.Type)" -ForegroundColor DarkYellow
        Write-Host "    Индикатор : $($ce.Indicator)" -ForegroundColor Yellow
        Write-Host "    Суть      : $($ce.Description)" -ForegroundColor Gray
    }
}

# ТОП КРИТИЧЕСКИХ НАХОДОК
if ($criticalFindings.Count -gt 0) {
    Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkRed
    Write-Host " [CRITICAL] КЛЮЧЕВЫЕ ДОКАЗАТЕЛЬСТВА ИСПОЛЬЗОВАНИЯ ЧИТОВ:" -ForegroundColor Red
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkRed
    
    # Группируем по уникальным файлам/артефактам, чтобы не загромождать консоль сотнями дублей
    $uniqueCritical = $criticalFindings | Group-Object Artifact | ForEach-Object { $_.Group[0] }
    
    foreach ($cf in $uniqueCritical) {
        $timeDisplay = if ($cf.Time -ne "Н/Д") { "[$($cf.Time)] " } else { "" }
        Write-Host "  -> $timeDisplay" -NoNewline -ForegroundColor DarkGray
        Write-Host "[$($cf.Category)] " -NoNewline -ForegroundColor Red
        Write-Host "$($cf.Artifact)" -ForegroundColor White
        Write-Host "     Детали: $($cf.Details)" -ForegroundColor Gray
    }
}

# СОПУТСТВУЮЩИЕ УЛИКИ (Клинеры, драйверы перехвата)
if ($highFindings.Count -gt 0) {
    Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkYellow
    Write-Host " [HIGH] СОПУТСТВУЮЩИЕ УТИЛИТЫ, ДРАЙВЕРЫ И КЛИНЕРЫ:" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkYellow
    
    $uniqueHigh = $highFindings | Group-Object Artifact | ForEach-Object { $_.Group[0] }
    foreach ($hf in $uniqueHigh) {
        $timeDisplay = if ($hf.Time -ne "Н/Д") { "[$($hf.Time)] " } else { "" }
        Write-Host "  -> $timeDisplay" -NoNewline -ForegroundColor DarkGray
        Write-Host "[$($hf.Category)] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($hf.Artifact)" -ForegroundColor White
        Write-Host "     Детали: $($hf.Details)" -ForegroundColor Gray
    }
}

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host " Проверка полностью завершена." -ForegroundColor DarkCyan
Write-Host "================================================================================`n" -ForegroundColor Cyan
