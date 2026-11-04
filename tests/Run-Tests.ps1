# Check-NikkeInfection.ps1 판정 테스트
#
# 임시 폴더에 가짜 Windows 사용자 폴더(AppData, Temp, NIKKE 설치 폴더)를 만들고,
# 감염 흔적 "문자열"만 담은 가짜 파일을 심은 뒤 점검 도구의 판정(종료 코드)을 확인합니다.
# 진짜 악성코드는 전혀 사용하지 않습니다.
#
# 실행: pwsh tests/Run-Tests.ps1   (Windows PowerShell 5.1: powershell -File tests\Run-Tests.ps1)
#
# 리눅스에서는 레지스트리, 네트워크, 디지털 서명 검사는 테스트되지 않습니다(Windows 전용 기능).
# 레지스트리 테스트는 실제 HKCU를 건드리므로 CI(GitHub Actions 등, 환경변수 CI 설정)에서만 실행합니다.

$ErrorActionPreference = 'Stop'
# 점검 도구의 한글 출력을 제대로 읽기 위해 (Windows PowerShell 5.1 기본값은 영문 코드페이지)
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$Checker = [IO.Path]::Combine($PSScriptRoot, '..', 'Check-NikkeInfection.ps1')
$Pwsh = (Get-Process -Id $PID).Path
$Hex64 = 'ab' * 32
$OnWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
$ClsidPath = 'HKCU:\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'

function New-FakeEnv([string]$Name) {
    $root = Join-Path ([IO.Path]::GetTempPath()) ("nikke-test-{0}-{1}" -f $Name, [guid]::NewGuid().ToString('N').Substring(0, 8))
    $e = [ordered]@{
        Root         = $root
        AppData      = Join-Path $root 'AppData/Roaming'
        LocalAppData = Join-Path $root 'AppData/Local'
        Temp         = Join-Path $root 'Temp'
        SystemRoot   = Join-Path $root 'Windows'
        Nikke        = Join-Path $root 'NIKKE'
    }
    $e.Cache = Join-Path $e.AppData 'nikke_launcher/tbs_cache'
    $e.Log   = Join-Path $e.Nikke 'Launcher/intl_service/debug.log'
    foreach ($d in @($e.AppData, $e.LocalAppData, $e.Temp,
                     (Join-Path $e.SystemRoot 'System32/drivers/etc'),
                     (Split-Path $e.Log),
                     (Join-Path $e.Cache 'Code Cache/js'),
                     (Join-Path $e.Cache 'Local Storage/leveldb'))) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
    Set-Content -Path (Join-Path $e.SystemRoot 'System32/drivers/etc/hosts') -Value '127.0.0.1 localhost'
    Set-Content -Path $e.Log -Value @('[1031/120000.001] launcher start', '[1031/120001.002] update check ok')
    # 정상 캐시 파일 (감염 문자열 없음)
    Set-Content -Path (Join-Path $e.Cache 'Code Cache/js/0000000000000000_0') -Value 'console.log("normal launcher code")'
    return $e
}

function Invoke-Checker($e) {
    $report = Join-Path $e.Root 'report.txt'
    $names = 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'SystemRoot', 'USERPROFILE'
    $saved = @{}
    foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
    try {
        $env:APPDATA = $e.AppData
        $env:LOCALAPPDATA = $e.LocalAppData
        $env:TEMP = $e.Temp
        # Windows에서 SystemRoot를 바꾸면 PowerShell이 시작하지 못하므로 리눅스에서만 가짜 경로 사용
        if (-not $OnWindows) {
            $env:SystemRoot = $e.SystemRoot
            $env:USERPROFILE = $e.Root
        }
        # PowerShell 5.1은 Stop 모드에서 외부 프로그램의 stderr 출력을 오류로 처리하므로 잠시 완화
        $ErrorActionPreference = 'Continue'
        $out = & $Pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Checker -NikkePath $e.Nikke -ReportPath $report *>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = 'Stop'
        foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
    }
    [pscustomobject]@{ Code = $code; Output = ($out | Out-String); Report = $report }
}

# ---------------------------------------------------------------------------
# 테스트 케이스: 이름, 기대 종료 코드, 결과에 들어 있어야 할 문구, 가짜 흔적을 심는 코드
#   0 = 흔적 없음, 1 = 감염 흔적 있음, 2 = 현재 감염, 3 = 의심
# ---------------------------------------------------------------------------
$Cases = @(
    @{ Name = '정상 PC'; Expect = 0; Contains = '알려진 감염 흔적 없음'; Setup = { param($e) } }

    @{ Name = '로그에 k2f_chan'; Expect = 1; Contains = 'k2f_chan registered'; Setup = {
        param($e)
        Add-Content -Path $e.Log -Value '[1103/204159.453] k2f_chan registered'
        Add-Content -Path $e.Log -Value '[1103/204200.001] agent started as DESKTOP-TEST'
    } }

    @{ Name = '로그에 페이로드 다운로드 시도'; Expect = 1; Contains = 'insight.bundle'; Setup = {
        param($e)
        Add-Content -Path $e.Log -Value '[2026-11-03 20:41:59.453] AddTask url=https://analytics.insightjs.com/comm/assets/insight.bundle'
    } }

    @{ Name = '변조된 JS 코드 캐시'; Expect = 1; Contains = 'images.7fec4c32.js'; Setup = {
        param($e)
        Set-Content -Path (Join-Path $e.Cache 'Code Cache/js/ce2fd3f1007a9fe9_0') -Value 'xx https://insightjs.com/l.js?f=images xx'
    } }

    @{ Name = 'Local Storage에 k2f.agent (UTF-16)'; Expect = 1; Contains = '악성 에이전트 상태'; Setup = {
        param($e)
        $bytes = [byte[]](1, 0, 0, 0) + [Text.Encoding]::Unicode.GetBytes('_https://x k2f.agent.state') + [byte[]](0, 0)
        [IO.File]::WriteAllBytes((Join-Path $e.Cache 'Local Storage/leveldb/000003.log'), $bytes)
    } }

    @{ Name = '비밀번호 수집 임시 파일'; Expect = 1; Contains = '임시 파일 발견'; Setup = {
        param($e)
        Set-Content -Path (Join-Path $e.Temp 'k2f-bcreds-1234') -Value 'fake'
    } }

    @{ Name = '64자리 폴더 속 악성 DLL'; Expect = 2; Contains = '현재 활성'; Setup = {
        param($e)
        $d = Join-Path $e.LocalAppData "Google/Chrome/User Data/PlatformExperienceHelper/$Hex64"
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        Set-Content -Path (Join-Path $d 'platform_experience_helper.dll') -Value 'MZ fake'
    } }

    @{ Name = '64자리 폴더 속 잔여 파일만'; Expect = 1; Contains = '잔여 파일'; Setup = {
        param($e)
        $d = Join-Path $e.LocalAppData "Google/Chrome/User Data/PlatformExperienceHelper/$Hex64"
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        Set-Content -Path (Join-Path $d 'old-clsid.txt') -Value 'fake'
    } }

    @{ Name = '평소와 다른 위치의 같은 이름 DLL'; Expect = 3; Contains = '의심 항목'; Setup = {
        param($e)
        $d = Join-Path $e.LocalAppData 'Google/Chrome/User Data/PlatformExperienceHelper/other'
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        Set-Content -Path (Join-Path $d 'platform_experience_helper.dll') -Value 'MZ fake'
    } }

    @{ Name = '정상 PlatformExperienceHelper 폴더만 있음'; Expect = 0; Contains = '악성 DLL이 없습니다'; Setup = {
        param($e)
        New-Item -ItemType Directory -Force -Path (Join-Path $e.LocalAppData 'Google/Chrome/User Data/PlatformExperienceHelper') | Out-Null
    } }
)

# ---------------------------------------------------------------------------
# Windows 전용: 레지스트리 테스트 (CI에서만)
# ---------------------------------------------------------------------------
if ($OnWindows -and $env:CI) {
    if (Test-Path -LiteralPath $ClsidPath) {
        throw "이미 $ClsidPath 키가 있습니다. 기존 키를 덮어쓰지 않도록 테스트를 중단합니다."
    }
    $RemoveClsid = { Remove-Item -LiteralPath $ClsidPath -Recurse -Force -ErrorAction SilentlyContinue }

    $Cases += @{ Name = '레지스트리 COM 하이재킹'; Expect = 2; Contains = '자동 실행되도록 등록'; Cleanup = $RemoveClsid; Setup = {
        param($e)
        $dll = Join-Path $e.LocalAppData "Google\Chrome\User Data\PlatformExperienceHelper\$Hex64\platform_experience_helper.dll"
        New-Item -Path "$ClsidPath\InprocServer32" -Force | Out-Null
        Set-Item -LiteralPath "$ClsidPath\InprocServer32" -Value $dll
    } }

    $Cases += @{ Name = '빈 CLSID 키만 남음'; Expect = 1; Contains = '빈 CLSID 키'; Cleanup = $RemoveClsid; Setup = {
        param($e)
        New-Item -Path $ClsidPath -Force | Out-Null
    } }

    $Cases += @{ Name = '시스템 폴더를 가리키는 CLSID'; Expect = 3; Contains = '재정의'; Cleanup = $RemoveClsid; Setup = {
        param($e)
        New-Item -Path "$ClsidPath\InprocServer32" -Force | Out-Null
        Set-Item -LiteralPath "$ClsidPath\InprocServer32" -Value 'C:\Windows\System32\wpc.dll'
    } }
}

Write-Host ("환경: PowerShell {0} / {1}" -f $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString)

$failed = 0
foreach ($c in $Cases) {
    $e = New-FakeEnv 'case'
    try {
        & $c.Setup $e
        $r = Invoke-Checker $e
        $problems = @()
        if ($r.Code -ne $c.Expect) { $problems += "종료 코드 {0} (기대값 {1})" -f $r.Code, $c.Expect }
        if ($r.Output -notlike "*$($c.Contains)*") { $problems += "출력에 '{0}' 없음" -f $c.Contains }
        if (-not (Test-Path $r.Report)) { $problems += '보고서 파일이 만들어지지 않음' }

        if ($problems.Count -eq 0) {
            Write-Host ("PASS  {0}" -f $c.Name) -ForegroundColor Green
        } else {
            $failed++
            Write-Host ("FAIL  {0}: {1}" -f $c.Name, ($problems -join ', ')) -ForegroundColor Red
            Write-Host ($r.Output -split "`n" | ForEach-Object { "      | $_" } | Out-String)
        }
    } finally {
        if ($c.Cleanup) { & $c.Cleanup }
        Remove-Item -Recurse -Force -Path $e.Root -ErrorAction SilentlyContinue
    }
}

Write-Host ''
if ($failed -eq 0) {
    Write-Host ("전체 {0}개 테스트 통과" -f $Cases.Count) -ForegroundColor Green
} else {
    Write-Host ("{0}/{1}개 실패" -f $failed, $Cases.Count) -ForegroundColor Red
}
exit $failed
