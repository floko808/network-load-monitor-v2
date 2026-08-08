#!/usr/bin/env bash
#
# Build and test both front ends for Linux and Windows.
#
#   ./build.sh              test, then build both targets into dist/
#   ./build.sh linux        Linux only
#   ./build.sh windows      Windows only
#   ./build.sh test         tests only
#
# The Windows target is cross-compiled with cargo-xwin, which needs no root:
#   cargo install cargo-xwin
#   rustup target add x86_64-pc-windows-msvc
# On first use it downloads the Microsoft CRT and Windows SDK headers/import
# libraries into the cargo cache; later builds are offline.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

WIN_TARGET=x86_64-pc-windows-msvc
DIST="$ROOT/dist"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mwarning: %s\033[0m\n' "$*" >&2; }
die() { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

run_tests() {
    say "Running tests"
    cargo test --workspace
}

build_linux() {
    say "Building for Linux (x86_64-unknown-linux-gnu)"
    cargo build --release --workspace
    mkdir -p "$DIST/linux"
    cp target/release/network-monitor "$DIST/linux/"
    cp target/release/network-monitor-gui "$DIST/linux/"
}

build_windows() {
    say "Building for Windows ($WIN_TARGET)"
    cargo xwin --version >/dev/null 2>&1 \
        || die "cargo-xwin not found. Install it with: cargo install cargo-xwin"
    rustup target list --installed | grep -qx "$WIN_TARGET" \
        || die "Rust target missing. Add it with: rustup target add $WIN_TARGET"

    cargo xwin build --release --workspace --target "$WIN_TARGET"
    mkdir -p "$DIST/windows"
    cp "target/$WIN_TARGET/release/network-monitor.exe" "$DIST/windows/"
    cp "target/$WIN_TARGET/release/network-monitor-gui.exe" "$DIST/windows/"
    check_portable
}

# Both executables must stand alone: no runtime to install, no DLL to copy
# alongside, nothing that a machine without a graphics driver cannot satisfy.
# The desktop build draws its interface on the CPU precisely so that it runs
# in a virtual machine, and importing a graphics library would quietly undo
# that — so it is checked rather than assumed.
check_portable() {
    command -v objdump >/dev/null 2>&1 || { warn "objdump not found; skipping portability check"; return 0; }
    local forbidden="opengl32|d3d12|d3d11|dxgi|vulkan|VCRUNTIME|MSVCP|api-ms-win-crt"
    local failed=0
    for exe in "$DIST/windows"/*.exe; do
        local hits
        hits=$(objdump -p "$exe" 2>/dev/null | grep -i "DLL Name" | grep -Ei "$forbidden" || true)
        if [ -n "$hits" ]; then
            printf '\033[1;31m%s depends on:\033[0m\n%s\n' "$(basename "$exe")" "$hits" >&2
            failed=1
        fi
    done
    [ "$failed" -eq 0 ] || die "Windows binaries are not self-contained (see above)"
    echo "  no graphics or C-runtime dependencies: ok"
}

# Verify each built binary at least starts and reports its own version, so a
# broken link or a missing runtime dependency fails here rather than on a
# substation laptop.
smoke_test() {
    say "Smoke-testing built binaries"
    if [ -x "$DIST/linux/network-monitor" ]; then
        "$DIST/linux/network-monitor" --version
        "$DIST/linux/network-monitor" --list >/dev/null && echo "  interface listing: ok"
    fi
    if [ -f "$DIST/windows/network-monitor.exe" ]; then
        if command -v wine >/dev/null 2>&1; then
            wine "$DIST/windows/network-monitor.exe" --version 2>/dev/null \
                || warn "wine could not run the Windows CLI; test it on Windows"
        else
            warn "wine not installed - Windows binaries built but not executed here"
        fi
    fi
}

# A binary copied to a substation laptop leaves this repository behind, and the
# license terms have to travel with it — both this project's own, and the
# attribution notices of the crates linked into it. Shipping dist/ without
# these is a license violation, so they are packaged rather than left to
# whoever does the copying.
#
# LICENSE-APACHE is here even though this project is MIT: winit and several
# other dependencies are Apache-2.0, which requires its text reach every
# recipient. It is a third-party notice, not a second license for this code.
copy_legal() {
    say "Adding license files"
    for f in LICENSE-MIT LICENSE-APACHE THIRD-PARTY-LICENSES.md; do
        [ -f "$ROOT/$f" ] || die "$f is missing; the distribution may not be shipped without it"
        cp "$ROOT/$f" "$DIST/"
    done
    printf '  %s\n' "LICENSE-MIT, LICENSE-APACHE, THIRD-PARTY-LICENSES.md: ok"
}

checksums() {
    say "SHA256 checksums"
    ( cd "$DIST" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2 | tee SHA256SUMS )
}

case "${1:-all}" in
    test)    run_tests ;;
    linux)   run_tests; build_linux; smoke_test; copy_legal; checksums ;;
    windows) run_tests; build_windows; smoke_test; copy_legal; checksums ;;
    all)     run_tests; build_linux; build_windows; smoke_test; copy_legal; checksums ;;
    *)       die "unknown target '$1' (expected: all, linux, windows, test)" ;;
esac

say "Done. Artifacts in $DIST"
