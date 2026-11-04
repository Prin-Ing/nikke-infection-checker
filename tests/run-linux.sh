#!/usr/bin/env bash
# 리눅스에서 테스트 실행
# 공식 PowerShell을 내려받아 SHA256을 검증하고, 일치할 때만 테스트를 돌립니다.
set -euo pipefail

PWSH_VERSION=7.6.9
# 출처: https://github.com/PowerShell/PowerShell/releases/tag/v7.6.9 (릴리스 노트와 hashes.sha256 두 곳에서 일치 확인)
PWSH_SHA256=1da6d6d6035d651f20e70ddee7c4c15ac6ab8b9fb40ee92240d91263f28a884b
PWSH_URL="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-x64.tar.gz"

if [ "$(uname -m)" != "x86_64" ]; then
    echo "x86_64 전용 스크립트입니다. (현재: $(uname -m))" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/nikke-checker"
PWSH_DIR="$CACHE_DIR/pwsh-$PWSH_VERSION"
mkdir -p "$CACHE_DIR"

if [ ! -x "$PWSH_DIR/pwsh" ]; then
    TGZ="$CACHE_DIR/pwsh-$PWSH_VERSION.tar.gz.part"
    echo "PowerShell $PWSH_VERSION 다운로드 중..."
    curl -fL --proto '=https' --tlsv1.2 -o "$TGZ" "$PWSH_URL"

    echo "SHA256 검증 중..."
    if ! echo "$PWSH_SHA256  $TGZ" | sha256sum -c --quiet -; then
        echo "SHA256 불일치! 변조됐거나 손상된 파일일 수 있습니다. 파일을 삭제하고 중단합니다." >&2
        echo "  기대값: $PWSH_SHA256" >&2
        echo "  실제값: $(sha256sum "$TGZ" | cut -d' ' -f1)" >&2
        rm -f "$TGZ"
        exit 1
    fi
    echo "SHA256 일치: $PWSH_SHA256"

    rm -rf "$PWSH_DIR.tmp"
    mkdir -p "$PWSH_DIR.tmp"
    tar xzf "$TGZ" -C "$PWSH_DIR.tmp"
    chmod +x "$PWSH_DIR.tmp/pwsh"
    mv "$PWSH_DIR.tmp" "$PWSH_DIR"
    rm -f "$TGZ"
fi

# ICU 라이브러리가 없으면 .NET이 시작하지 못하므로 국제화 기능 없이 실행
if ! ldconfig -p 2>/dev/null | grep -q libicuuc; then
    export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
fi

exec "$PWSH_DIR/pwsh" -NoProfile -NonInteractive "$HERE/Run-Tests.ps1"
