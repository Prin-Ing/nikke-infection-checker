# NIKKE PC 런처 악성코드 감염 점검 도구

2026년 9~11월에 NIKKE PC 런처를 통해 퍼진 원격제어/정보탈취 악성코드(insightjs, k2f 에이전트)에
감염됐는지 확인하는 Windows용 도구입니다. **읽기 전용**이라 아무것도 수정하거나 삭제하지 않습니다.

## 사용법

0. **(권장) 받은 파일이 변조되지 않았는지 확인합니다.** 아래 [파일 무결성 확인](#파일-무결성-확인)을 보세요.
1. 이 폴더를 Windows PC로 복사합니다.
2. `Run-Check.cmd`를 더블클릭합니다.
   (관리자 권한으로 실행하면 실행 중인 프로그램을 더 정확하게 검사할 수 있습니다.)
3. 결과는 화면에 나오고, 바탕화면에 `NIKKE_감염점검_날짜.txt`로도 저장됩니다.

NIKKE를 기본 위치가 아닌 곳에 설치했다면 PowerShell에서 직접 지정하세요:

```powershell
powershell -ExecutionPolicy Bypass -File .\Check-NikkeInfection.ps1 -NikkePath 'D:\Games\NIKKE'
```

## 검사 항목

| # | 항목 | 내용 |
|---|------|------|
| 1 | 설치 폴더 | 레지스트리와 흔한 경로에서 NIKKE 런처 폴더 찾기 |
| 2 | 런처 로그 | `Launcher\intl_service\debug.log` 등에서 `k2f_chan registered`, `agent started as`, `insightjs` 검색 |
| 3 | 런처 캐시 | `%APPDATA%\nikke_launcher\tbs_cache`에서 변조된 JS 캐시, `k2f.agent` 상태, 공격자 주소 |
| 4 | 임시 파일 | `%TEMP%\k2f-bcreds-*`, `k2f_screen_*` (비밀번호/화면 수집 흔적) |
| 5 | 자동 실행 | `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` 하이재킹 |
| 6 | 악성 DLL | `...\User Data\PlatformExperienceHelper\<64자리>\platform_experience_helper.dll` |
| 7 | 실행 중 | 악성 DLL을 불러온 프로세스, 실행 중인 런처 |
| 8 | 네트워크 | 공격자 IP 연결, DNS 캐시, hosts 차단 여부 |

## 결과 판정

| 판정 | 뜻 | 종료 코드 |
|------|----|----|
| 감염됨 (현재 활성) | 악성코드가 지금도 자동 실행되거나 동작 중 | 2 |
| 감염 흔적 있음 | 과거에 실행된 적 있음. 정보 유출 가능성 | 1 |
| 의심 항목 있음 | 직접 확인 필요 | 3 |
| 알려진 흔적 없음 | 공개된 지표가 발견되지 않음 | 0 |

## 파일 무결성 확인

`SHA256SUMS` 파일에 배포 파일의 SHA256 해시가 들어 있습니다. 받은 파일의 해시가 같아야 원본입니다.

Windows (PowerShell):

```powershell
Get-FileHash .\Check-NikkeInfection.ps1, .\Run-Check.cmd -Algorithm SHA256 | Format-List Path, Hash
Get-Content .\SHA256SUMS
```

두 결과의 해시 값을 비교하세요(대소문자는 상관없음).

Linux / macOS:

```bash
sha256sum -c SHA256SUMS
```

**주의:** 파일과 해시를 같은 곳에서 받으면, 그곳이 해킹됐을 때 둘 다 바뀔 수 있습니다.
해시는 배포자가 따로 올린 곳(예: 커뮤니티 글 본문)의 값과 비교하는 것이 안전합니다.

## 테스트 (개발용)

리눅스에서 가짜 감염 환경을 만들어 판정이 맞는지 확인합니다. 진짜 악성코드는 쓰지 않습니다.

```bash
bash tests/run-linux.sh
```

공식 PowerShell을 내려받아 **SHA256을 검증한 뒤에만** 실행하고, 해시가 다르면 파일을 지우고 중단합니다.
레지스트리, 네트워크, 디지털 서명 검사는 Windows 전용이라 리눅스 테스트에서는 빠집니다.

파일을 고친 뒤에는 해시를 다시 만드세요:

```bash
sha256sum Check-NikkeInfection.ps1 Run-Check.cmd > SHA256SUMS
```

## 주의

- 공개된 지표만 확인합니다. "흔적 없음"이 100% 안전을 보장하지 않습니다. 백신 정밀 검사도 함께 하세요.
- 지표는 커뮤니티 분석 결과이며, 아직 Level Infinite/시프트업의 공식 확인은 없습니다(2026-11-04 기준).
- 현재 로그인한 Windows 사용자 계정만 검사합니다.

## 지표 출처

- MotherSphere 분석 보고서: https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5
- whykusanagi 탐지/제거 키트: https://github.com/whykusanagi/nikke_malware
