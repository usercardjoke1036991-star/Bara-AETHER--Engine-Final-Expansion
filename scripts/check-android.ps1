# Comprueba el kernel en aarch64-linux-android.
# `cargo check` no enlaza: basta el rust-std de ese target, sin NDK.
# La bilattice de Belnap vive en el mismo crate y viaja con este target.

$ErrorActionPreference = "Stop"
$workspace = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $workspace
rustup target add aarch64-linux-android
cargo check -p bara --target aarch64-linux-android
