<#
.SYNOPSIS
    NIKKE PC 런처 악성코드(insightjs / k2f 에이전트) 감염 여부 점검 도구

.DESCRIPTION
    2026년 9~11월 NIKKE PC 런처 공급망 공격에서 공개된 감염 지표(IOC)를 검사합니다.
    이 스크립트는 읽기 전용입니다. 파일, 레지스트리, 설정을 아무것도 바꾸거나 지우지 않습니다.

    지표 출처:
      https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5
      https://github.com/whykusanagi/nikke_malware

    판정 등급:
      ACTIVE  - 지금도 감염된 상태 (자동 실행 등록, 악성 DLL, 공격 서버 연결 등)
      EXPOSED - 악성코드가 실행된 흔적 (로그, 캐시, 임시 파일)
      WARN    - 의심스러우나 단정할 수 없음 (직접 확인 필요)
      INFO    - 참고 정보

.PARAMETER NikkePath
    NIKKE 설치 폴더를 직접 지정합니다. 자동으로 못 찾을 때 사용하세요. 예: -NikkePath 'D:\Games\NIKKE'

.PARAMETER ReportPath
    결과 보고서를 저장할 경로. 기본값은 바탕화면입니다.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Check-NikkeInfection.ps1
#>
[CmdletBinding()]
param(
    [string[]]$NikkePath,
    [string]$ReportPath
)

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$ScriptVersion = '1.0.0'

# ---------------------------------------------------------------------------
# 감염 지표 (IOC)
# ---------------------------------------------------------------------------
$IocDomains   = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')
$IocIPs       = @('89.127.233.127', '89.126.250.172')
$MaliciousClsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'

# 런처 로그에서 찾을 문자열: 문자열 -> 설명
$LogMarkers = [ordered]@{
    'k2f_chan registered' = '악성 에이전트가 등록됨 (가장 강력한 감염 지표)'
    'agent started as'    = '악성 에이전트가 실행됨'
    'insight.bundle'      = '악성 페이로드(insight.bundle) 다운로드 시도'
    'insightjs'           = '공격자 도메인(insightjs) 접속 시도'
    'lua downloaded to'   = '악성 Lua 스크립트 다운로드'
}

# 런처 캐시(tbs_cache) 안에서 찾을 문자열
$CacheMarkers = @('insightjs', 'k2f.agent', 'k2f_chan', 'insight.bundle')

# 변조된 JS 파일의 Code Cache 항목 이름
$CodeCacheEntries = [ordered]@{
    'dd65fa4d61079e7e_0' = 'aegis-fix.min.js'
    'ce2fd3f1007a9fe9_0' = 'images.7fec4c32.js'
    '1416c638b3830103_0' = 'FeedList.feb647c9.js'
    'fd520c7c0f65c2d7_0' = 'vue-bucket.min.js'
}

# ---------------------------------------------------------------------------
# 도우미 함수
# ---------------------------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]
$ReportLines = New-Object System.Collections.Generic.List[string]

function Write-Line([string]$Text, [string]$Color = 'White') {
    Write-Host $Text -ForegroundColor $Color
    $ReportLines.Add($Text)
}

function Write-Section([string]$Title) {
    Write-Line ''
    Write-Line ("== {0} " -f $Title).PadRight(70, '=') 'Cyan'
}

function Add-Finding([string]$Level, [string]$Message, [string]$Evidence) {
    $Findings.Add([pscustomobject]@{ Level = $Level; Message = $Message; Evidence = $Evidence })
    $colors = @{ ACTIVE = 'Red'; EXPOSED = 'Yellow'; WARN = 'Magenta'; INFO = 'Gray' }
    Write-Line ("  [{0}] {1}" -f $Level, $Message) $colors[$Level]
    if ($Evidence) { Write-Line ("          {0}" -f $Evidence) 'DarkGray' }
}

function Write-Ok([string]$Message) {
    Write-Line ("  [OK] {0}" -f $Message) 'Green'
}

$Latin1 = [Text.Encoding]::GetEncoding(28591)

# 파일에 특정 문자열이 들어 있는지 바이트 단위로 검사 (ASCII와 UTF-16 모두).
# 런처가 실행 중이어도 읽을 수 있도록 공유 모드로 엽니다.
function Get-FileMarkerHits([string]$Path, [string[]]$Patterns, [long]$MaxBytes = 64MB) {
    $hits = @()
    try {
        $fi = Get-Item -LiteralPath $Path -Force
        if ($fi.PSIsContainer -or $fi.Length -eq 0 -or $fi.Length -gt $MaxBytes) { return $hits }
        $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $fs = [IO.File]::Open($fi.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
        try {
            $buf = New-Object byte[] $fi.Length
            $read = 0
            while ($read -lt $buf.Length) {
                $n = $fs.Read($buf, $read, $buf.Length - $read)
                if ($n -le 0) { break }
                $read += $n
            }
        } finally { $fs.Dispose() }
        $text = $Latin1.GetString($buf, 0, $read)
        foreach ($p in $Patterns) {
            $utf16 = -join ($p.ToCharArray() | ForEach-Object { "$_" + [char]0 })
            if ($text.IndexOf($p, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $text.IndexOf($utf16, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hits += $p
            }
        }
    } catch {}
    return $hits
}

function Get-SignatureText([string]$Path) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '서명자 없음' }
        return ("서명 상태: {0} / {1}" -f $sig.Status, $signer)
    } catch { return '서명 확인 실패' }
}

# ---------------------------------------------------------------------------
# 시작
# ---------------------------------------------------------------------------
Write-Line ("NIKKE PC 런처 악성코드 감염 점검 v{0}" -f $ScriptVersion) 'Cyan'
Write-Line ("점검 시각: {0}   컴퓨터: {1}   사용자: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $env:USERNAME)
Write-Line '이 도구는 읽기 전용입니다. 아무것도 수정하거나 삭제하지 않습니다.' 'DarkGray'

# ---------------------------------------------------------------------------
# 1. NIKKE 설치 폴더 찾기
# ---------------------------------------------------------------------------
Write-Section '1. NIKKE 설치 폴더 찾기'

$candidates = New-Object System.Collections.Generic.List[string]
if ($NikkePath) { $NikkePath | ForEach-Object { $candidates.Add($_) } }

# 설치 프로그램 목록(레지스트리)에서 찾기
$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($root in $uninstallRoots) {
    Get-ItemProperty -Path $root | Where-Object { $_.DisplayName -match 'NIKKE|니케' } | ForEach-Object {
        if ($_.InstallLocation) { $candidates.Add($_.InstallLocation.Trim('"')) }
        if ($_.DisplayIcon) {
            $iconPath = ($_.DisplayIcon -split ',')[0].Trim('"')
            if ($iconPath) { $candidates.Add((Split-Path -Parent $iconPath)) }
        }
    }
}

# 흔한 설치 위치
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $r = $_.Root
    $candidates.Add((Join-Path $r 'NIKKE'))
    $candidates.Add((Join-Path $r 'Program Files\NIKKE'))
    $candidates.Add((Join-Path $r 'Program Files (x86)\NIKKE'))
    $candidates.Add((Join-Path $r 'Games\NIKKE'))
}

# Launcher 폴더 또는 intl_service 폴더가 있는 곳만 남기기
$launcherDirs = New-Object System.Collections.Generic.List[string]
foreach ($c in ($candidates | Select-Object -Unique)) {
    if (-not $c -or -not (Test-Path -LiteralPath $c)) { continue }
    $item = Get-Item -LiteralPath $c -Force
    # 사용자가 Launcher 폴더 자체나 그 하위를 지정한 경우까지 처리
    $probe = @($item.FullName, (Join-Path $item.FullName 'Launcher'), $item.Parent.FullName)
    foreach ($p in $probe) {
        if ($p -and (Test-Path -LiteralPath (Join-Path $p 'intl_service'))) { $launcherDirs.Add((Get-Item -LiteralPath $p).FullName) }
    }
    if (-not ($launcherDirs | Where-Object { $_ -like "$($item.FullName)*" })) {
        Get-ChildItem -LiteralPath $item.FullName -Directory -Recurse -Depth 3 -Filter 'intl_service' -Force |
            ForEach-Object { $launcherDirs.Add($_.Parent.FullName) }
    }
}
$launcherDirs = @($launcherDirs | Select-Object -Unique)

$appCache = Join-Path $env:APPDATA 'nikke_launcher\tbs_cache'
$hasAppCache = Test-Path -LiteralPath $appCache

if ($launcherDirs.Count -gt 0) {
    foreach ($d in $launcherDirs) { Add-Finding 'INFO' 'NIKKE 런처 폴더 발견' $d }
} else {
    Add-Finding 'INFO' 'NIKKE 런처 설치 폴더를 찾지 못했습니다. 다른 곳에 설치했다면 -NikkePath 로 지정하세요.' ''
}
if ($hasAppCache) { Add-Finding 'INFO' 'NIKKE 런처 캐시 폴더 발견' $appCache }

# ---------------------------------------------------------------------------
# 2. 런처 로그 검사
# ---------------------------------------------------------------------------
Write-Section '2. 런처 로그 검사 (debug.log 등)'

$logHitCount = 0
foreach ($d in $launcherDirs) {
    $logs = Get-ChildItem -LiteralPath $d -Recurse -Depth 4 -File -Force -Include '*.log', '*.log.*', '*.txt' |
        Where-Object { $_.Length -lt 512MB }
    foreach ($log in $logs) {
        foreach ($marker in $LogMarkers.Keys) {
            $m = Select-String -LiteralPath $log.FullName -Pattern $marker -SimpleMatch | Select-Object -First 2
            if ($m) {
                $logHitCount++
                $lines = ($m | ForEach-Object { "줄 {0}: {1}" -f $_.LineNumber, $_.Line.Trim() }) -join ' | '
                if ($lines.Length -gt 300) { $lines = $lines.Substring(0, 300) + '...' }
                Add-Finding 'EXPOSED' ("{0}  ['{1}']" -f $LogMarkers[$marker], $marker) ("{0}  -> {1}" -f $log.FullName, $lines)
            }
        }
    }

    # 악성 Lua 임시 파일 (실행 후 지워지지만 남아 있을 수 있음)
    $tinyget = Join-Path $d 'log\tinyget'
    if (Test-Path -LiteralPath $tinyget) {
        Get-ChildItem -LiteralPath $tinyget -File -Force | Where-Object { $_.Name -like 'k2f*.lua' -or $_.Name -like 'tinyget.*.log' -or $_.Name -like 'tinyget.mem.log' } | ForEach-Object {
            $hits = Get-FileMarkerHits $_.FullName @('k2f', 'insightjs')
            if ($hits) {
                $logHitCount++
                Add-Finding 'EXPOSED' '악성 Lua 페이로드 파일 발견' ("{0} (포함: {1})" -f $_.FullName, ($hits -join ', '))
            }
        }
    }
}
if ($launcherDirs.Count -eq 0) {
    Write-Line '  (런처 폴더가 없어 건너뜀)' 'DarkGray'
} elseif ($logHitCount -eq 0) {
    Write-Ok '런처 로그에서 감염 흔적을 찾지 못했습니다.'
}

# ---------------------------------------------------------------------------
# 3. 런처 캐시 검사 (%APPDATA%\nikke_launcher\tbs_cache)
# ---------------------------------------------------------------------------
Write-Section '3. 런처 캐시 검사 (tbs_cache)'

if ($hasAppCache) {
    $cacheHitCount = 0

    # 3-1. 변조된 JS의 Code Cache 항목
    $codeCacheDir = Join-Path $appCache 'Code Cache\js'
    foreach ($entry in $CodeCacheEntries.Keys) {
        $p = Join-Path $codeCacheDir $entry
        if (Test-Path -LiteralPath $p) {
            $hits = Get-FileMarkerHits $p @('insightjs')
            if ($hits) {
                $cacheHitCount++
                Add-Finding 'EXPOSED' ("변조된 {0} 가 캐시에 남아 있음 (악성 코드 실행됨)" -f $CodeCacheEntries[$entry]) $p
            }
        }
    }

    # 3-2. 캐시 전체에서 악성 문자열 검색
    $hitFiles = @{}
    Get-ChildItem -LiteralPath $appCache -Recurse -File -Force | ForEach-Object {
        $hits = Get-FileMarkerHits $_.FullName $CacheMarkers
        foreach ($h in $hits) {
            if (-not $hitFiles.ContainsKey($h)) { $hitFiles[$h] = New-Object System.Collections.Generic.List[string] }
            $hitFiles[$h].Add($_.FullName)
        }
    }
    foreach ($h in $hitFiles.Keys) {
        $cacheHitCount++
        $files = $hitFiles[$h]
        $shown = ($files | Select-Object -First 3) -join ' | '
        if ($files.Count -gt 3) { $shown += (" 외 {0}개" -f ($files.Count - 3)) }
        $desc = switch ($h) {
            'k2f.agent' { '악성 에이전트 상태 정보가 저장돼 있음 (게임을 지워도 남는 흔적)' }
            'k2f_chan'  { '악성 에이전트 통신 채널 흔적' }
            default     { "공격자 서버 주소('$h')가 캐시에 기록돼 있음" }
        }
        Add-Finding 'EXPOSED' $desc $shown
    }

    if ($cacheHitCount -eq 0) { Write-Ok '런처 캐시에서 감염 흔적을 찾지 못했습니다.' }
} else {
    Write-Line '  (캐시 폴더가 없어 건너뜀)' 'DarkGray'
}

# ---------------------------------------------------------------------------
# 4. 임시 파일 검사 (탈취한 비밀번호/스크린샷 임시 파일)
# ---------------------------------------------------------------------------
Write-Section '4. 임시 파일 검사 (%TEMP%)'

$tempHits = @()
foreach ($pattern in @('k2f-bcreds-*', 'k2f_screen_*', 'k2f*.lua')) {
    $tempHits += Get-ChildItem -LiteralPath $env:TEMP -Filter $pattern -Force
}
if ($tempHits.Count -gt 0) {
    $shown = ($tempHits | Select-Object -First 5 | ForEach-Object { "{0} ({1:yyyy-MM-dd HH:mm})" -f $_.FullName, $_.LastWriteTime }) -join ' | '
    Add-Finding 'EXPOSED' '악성코드가 비밀번호/화면을 수집할 때 만드는 임시 파일 발견' $shown
} else {
    Write-Ok '악성 임시 파일이 없습니다.'
}

# ---------------------------------------------------------------------------
# 5. 자동 실행 등록 검사 (레지스트리 COM 하이재킹)
# ---------------------------------------------------------------------------
Write-Section '5. 자동 실행 등록 검사 (레지스트리)'

$clsidKey = "HKCU:\Software\Classes\CLSID\$MaliciousClsid"
$inprocKey = "$clsidKey\InprocServer32"
if (Test-Path -LiteralPath $clsidKey) {
    $dllPath = $null
    if (Test-Path -LiteralPath $inprocKey) { $dllPath = (Get-Item -LiteralPath $inprocKey).GetValue('') }
    if ($dllPath) {
        $expanded = [Environment]::ExpandEnvironmentVariables($dllPath)
        if ($expanded -match 'User Data|PlatformExperienceHelper|platform_experience_helper|AppData') {
            Add-Finding 'ACTIVE' '악성 DLL이 자동 실행되도록 등록돼 있음 (Windows 자녀 보호 기능으로 위장)' ("{0} = {1}" -f $inprocKey, $dllPath)
        } else {
            Add-Finding 'WARN' '사용자 영역에 이 CLSID가 재정의돼 있음 (정상이라면 HKLM의 wpc.dll만 있어야 함)' ("{0} = {1}" -f $inprocKey, $dllPath)
        }
    } else {
        Add-Finding 'EXPOSED' '빈 CLSID 키가 남아 있음 (악성코드가 스스로 제거하면서 남긴 흔적일 수 있음)' $clsidKey
    }
} else {
    Write-Ok '악성 자동 실행 등록이 없습니다. (HKLM 쪽 같은 CLSID는 정상 wpc.dll이므로 검사 대상이 아닙니다)'
}

# ---------------------------------------------------------------------------
# 6. 악성 DLL 파일 검사
# ---------------------------------------------------------------------------
Write-Section '6. 악성 DLL 파일 검사'

$dllNames = @('platform_experience_helper.dll', 'platform_experience_helper.dll.old', 'service_util.dll', 'old-clsid.txt')
$dllFound = @()
foreach ($root in @($env:LOCALAPPDATA, $env:APPDATA)) {
    if (-not $root) { continue }
    Get-ChildItem -LiteralPath $root -Directory -Recurse -Depth 5 -Filter 'PlatformExperienceHelper' -Force | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -File -Recurse -Depth 2 -Force | Where-Object { $dllNames -contains $_.Name } | ForEach-Object { $dllFound += $_ }
    }
}
foreach ($f in ($dllFound | Sort-Object FullName -Unique)) {
    $parentName = $f.Directory.Name
    $isHexFolder = $parentName -match '^[0-9a-fA-F]{64}$'
    $evidence = "{0}  수정: {1:yyyy-MM-dd HH:mm}  {2}" -f $f.FullName, $f.LastWriteTime, (Get-SignatureText $f.FullName)
    if ($f.Name -eq 'platform_experience_helper.dll' -and $isHexFolder) {
        Add-Finding 'ACTIVE' '악성 DLL 발견 (브라우저 폴더 안 64자리 해시 이름 폴더)' $evidence
    } elseif ($isHexFolder) {
        Add-Finding 'EXPOSED' '악성 DLL 관련 잔여 파일 발견' $evidence
    } else {
        Add-Finding 'WARN' '이름이 같은 파일 발견 (위치가 평소와 달라 직접 확인 필요)' $evidence
    }
}
if ($dllFound.Count -eq 0) { Write-Ok '악성 DLL이 없습니다.' }

# ---------------------------------------------------------------------------
# 7. 실행 중인 프로그램에 악성 DLL이 로드됐는지
# ---------------------------------------------------------------------------
Write-Section '7. 실행 중인 프로그램 검사'

$loaded = @()
foreach ($proc in Get-Process) {
    try {
        foreach ($mod in $proc.Modules) {
            if ($mod.ModuleName -ieq 'platform_experience_helper.dll' -and $mod.FileName -notmatch '\\Application\\') {
                $loaded += ("{0} (PID {1}) -> {2}" -f $proc.ProcessName, $proc.Id, $mod.FileName)
            }
        }
    } catch {}
}
if ($loaded.Count -gt 0) {
    Add-Finding 'ACTIVE' '악성 DLL이 지금 메모리에서 실행 중' ($loaded -join ' | ')
} else {
    Write-Ok '악성 DLL을 불러온 프로그램이 없습니다. (관리자 권한이 아니면 일부 프로그램은 확인 못 할 수 있음)'
}

$launcherProcs = Get-Process | Where-Object { $_.ProcessName -match '^(nikke_launcher|tbs_browser)$' }
if ($launcherProcs) {
    Add-Finding 'WARN' 'NIKKE 런처가 지금 실행 중입니다. 공식 해결 발표 전까지는 끄는 것을 권장합니다.' (($launcherProcs | ForEach-Object { "{0} (PID {1})" -f $_.ProcessName, $_.Id }) -join ', ')
}

# ---------------------------------------------------------------------------
# 8. 네트워크 검사 (공격자 서버 연결 / DNS 기록)
# ---------------------------------------------------------------------------
Write-Section '8. 네트워크 검사'

$netHit = $false
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conns = Get-NetTCPConnection | Where-Object { $IocIPs -contains $_.RemoteAddress }
    foreach ($c in $conns) {
        $netHit = $true
        $pname = (Get-Process -Id $c.OwningProcess).ProcessName
        Add-Finding 'ACTIVE' '공격자 서버와 연결돼 있음' ("{0}:{1} 상태 {2}, 프로그램 {3} (PID {4})" -f $c.RemoteAddress, $c.RemotePort, $c.State, $pname, $c.OwningProcess)
    }
}
if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $dns = Get-DnsClientCache | Where-Object { $_.Entry -match 'insightjs' -or $IocIPs -contains $_.Data }
    foreach ($e in ($dns | Sort-Object Entry -Unique)) {
        $netHit = $true
        Add-Finding 'EXPOSED' '최근 공격자 도메인에 접속한 기록 (DNS 캐시)' ("{0} -> {1}" -f $e.Entry, $e.Data)
    }
}
if (-not $netHit) { Write-Ok '공격자 서버 연결이나 최근 접속 기록이 없습니다. (DNS 캐시는 재부팅하면 지워지므로 과거 접속까지 보장하지는 않음)' }

$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsText = Get-Content -LiteralPath $hostsFile -Raw
if ($hostsText -match '(?m)^\s*[0-9.:]+\s+(analytics\.)?insightjs\.com') {
    Add-Finding 'INFO' 'hosts 파일에서 공격자 도메인이 차단돼 있습니다.' $hostsFile
} else {
    Add-Finding 'INFO' 'hosts 파일에 공격자 도메인 차단이 없습니다. (선택 사항: 차단하면 재감염 위험이 줄어듭니다)' ''
}

# ---------------------------------------------------------------------------
# 최종 판정
# ---------------------------------------------------------------------------
Write-Section '최종 판정'

$active  = @($Findings | Where-Object Level -eq 'ACTIVE')
$exposed = @($Findings | Where-Object Level -eq 'EXPOSED')
$warn    = @($Findings | Where-Object Level -eq 'WARN' | Where-Object { $_.Message -notlike 'NIKKE 런처가 지금 실행 중*' })

if ($active.Count -gt 0) {
    $exitCode = 2
    Write-Line '  >>> 감염됨 (현재 활성 상태) <<<' 'Red'
    Write-Line ''
    Write-Line '  지금 할 일:' 'Red'
    Write-Line '   1. 인터넷 연결을 끊으세요 (랜선 뽑기 / Wi-Fi 끄기).'
    Write-Line '   2. 다른 안전한 기기(스마트폰 등)에서 비밀번호를 바꾸세요.'
    Write-Line '      순서: NIKKE/Level Infinite -> 이메일 -> 은행/결제 -> 브라우저에 저장된 모든 사이트'
    Write-Line '   3. 모든 계정에서 "모든 기기 로그아웃" 후 2단계 인증을 켜세요.'
    Write-Line '   4. 암호화폐 지갑이 있다면 새 지갑(새 시드)으로 자산을 옮기세요.'
    Write-Line '   5. 공격자가 임의 명령을 실행할 수 있었으므로 Windows 재설치(초기화)가 가장 안전합니다.'
    Write-Line '      당장 재설치가 어렵다면: 위 레지스트리 키 삭제 -> 재부팅 -> 64자리 이름 폴더 삭제'
    Write-Line '      (상위 PlatformExperienceHelper 폴더는 정상 Chrome 폴더이므로 지우지 마세요)'
} elseif ($exposed.Count -gt 0) {
    $exitCode = 1
    Write-Line '  >>> 감염 흔적 있음 (악성코드가 이 PC에서 실행된 적 있음) <<<' 'Yellow'
    Write-Line ''
    Write-Line '  지금 상주 중인 악성코드는 발견되지 않았지만, 실행되던 동안 정보가 유출됐을 수 있습니다.' 'Yellow'
    Write-Line '   1. 다른 안전한 기기에서 비밀번호를 바꾸고 2단계 인증을 켜세요.'
    Write-Line '      순서: NIKKE/Level Infinite -> 이메일 -> 은행/결제 -> 브라우저에 저장된 모든 사이트'
    Write-Line '   2. 암호화폐 지갑이 있다면 새 지갑으로 자산을 옮기세요.'
    Write-Line '   3. 런처를 다시 켜기 전에 %APPDATA%\nikke_launcher\tbs_cache 폴더를 지우세요.'
    Write-Line '   4. 실행 중 공격자가 다른 것을 설치했을 수 있으므로 Windows 초기화를 권장합니다.'
} elseif ($warn.Count -gt 0) {
    $exitCode = 3
    Write-Line '  >>> 의심 항목 있음 (직접 확인 필요) <<<' 'Magenta'
    Write-Line '  위의 [WARN] 항목을 확인하세요. 판단이 어렵다면 결과 보고서를 보안 커뮤니티에 공유해 도움을 받으세요.'
} else {
    $exitCode = 0
    Write-Line '  >>> 알려진 감염 흔적 없음 <<<' 'Green'
    if ($launcherDirs.Count -eq 0 -and -not $hasAppCache) {
        Write-Line '  이 PC에서 NIKKE PC 런처 흔적을 찾지 못했습니다. 해당 사항이 없을 가능성이 높습니다.'
    } else {
        Write-Line '  공식 해결 발표 전까지는 PC 런처 실행을 미루는 것을 권장합니다.'
    }
}

Write-Line ''
Write-Line '  참고: 이 도구는 지금까지 공개된 지표만 확인합니다. "흔적 없음"이 100% 안전을 뜻하지는 않으며,' 'DarkGray'
Write-Line '        흔적은 시간이 지나거나 캐시를 지우면 사라질 수 있습니다. 백신 정밀 검사도 함께 하세요.' 'DarkGray'
Write-Line '        이 점검은 현재 Windows 사용자 계정만 대상으로 합니다.' 'DarkGray'

# ---------------------------------------------------------------------------
# 보고서 저장
# ---------------------------------------------------------------------------
if (-not $ReportPath) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop) { $desktop = $env:USERPROFILE }
    $ReportPath = Join-Path $desktop ("NIKKE_감염점검_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
try {
    $ReportLines | Out-File -LiteralPath $ReportPath -Encoding utf8 -ErrorAction Stop
    Write-Line ''
    Write-Line ("결과 보고서 저장: {0}" -f $ReportPath) 'Cyan'
} catch {
    Write-Host ("보고서 저장 실패: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

exit $exitCode
