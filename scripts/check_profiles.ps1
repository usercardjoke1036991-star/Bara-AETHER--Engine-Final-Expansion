<#
.SYNOPSIS
    Guarda de divergencia del perfil release del kernel Bara (AETHER-Omega).
.DESCRIPTION
    El kernel declara su `[profile.release]` en `.cargo/config.toml` y NO en
    `Cargo.toml`, porque Cargo solo admite perfiles en el manifiesto de la raiz
    del workspace: declararlos en un miembro emite el aviso «profiles for the
    non root package will be ignored» y ademas los ignora de verdad (LTO
    desactivado, mas unidades de codigo, `panic` unwind).

    Como el perfil de `.cargo/config.toml` se resuelve por directorio de
    trabajo, hay dos declaraciones legitimas: la del paquete suelto (CI,
    autohospedaje) y la del contenedor de desarrollo. Esta guarda falla si
    dejan de ser identicas, que es la unica derivacion silenciosa posible.
.PARAMETER WorkspaceRoot
    Ruta al manifiesto raiz del workspace contenedor. Si se omite, se busca
    subiendo desde la raiz del repositorio un `Cargo.toml` con `[workspace]`.
.EXAMPLE
    ./scripts/check_profiles.ps1
    ./scripts/check_profiles.ps1 -WorkspaceRoot ../Cargo.toml
.NOTES
    Ruta oficial versionada: scripts/check_profiles.ps1
    Codigo de salida: 0 = perfiles coherentes, 1 = divergencia o perfil ilegible.
#>
[CmdletBinding()]
param(
    [string]$WorkspaceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$ConfigPath = Join-Path $RepoRoot '.cargo/config.toml'

# Claves exigidas por el kernel, con su valor canonico textual.
$Expected = [ordered]@{
    'opt-level'     = '3'
    'lto'           = 'true'
    'codegen-units' = '1'
    'panic'         = '"abort"'
}

# Extrae la tabla [profile.release] de un TOML sin dependencias externas.
function Read-ReleaseProfile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $values = [ordered]@{}
    $inside = $false
    foreach ($raw in (Get-Content -LiteralPath $Path)) {
        $line = $raw.Trim()
        if ($line -match '^\[(?<name>[^\]]+)\]') {
            $inside = ($Matches['name'].Trim() -eq 'profile.release')
            continue
        }
        if (-not $inside) { continue }
        $line = ($line -split '#')[0].Trim()
        if ($line -eq '' -or $line -notmatch '=') { continue }
        $key, $value = $line -split '=', 2
        $values[$key.Trim()] = $value.Trim()
    }
    return $values
}

# Compara una tabla contra el perfil canonico del kernel.
function Compare-ReleaseProfile {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)]$Actual
    )

    $coherent = $true
    foreach ($key in $Expected.Keys) {
        $want = $Expected[$key]
        if (-not $Actual.Contains($key)) {
            Write-Host ('  ' + $Label + ': falta `' + $key + '`') -ForegroundColor Red
            $coherent = $false
            continue
        }
        $got = $Actual[$key]
        if ($got -ne $want) {
            Write-Host ('  ' + $Label + ': `' + $key + '` = ' + $got + ' (se exigia ' + $want + ')') -ForegroundColor Red
            $coherent = $false
        }
    }
    foreach ($key in $Actual.Keys) {
        if (-not $Expected.Contains($key)) {
            Write-Host ('  ' + $Label + ': clave sobrante `' + $key + '`') -ForegroundColor Red
            $coherent = $false
        }
    }
    return $coherent
}

try {
    Write-Host 'Bara (AETHER-Omega) - perfil release del kernel' -ForegroundColor Cyan

    $kernel = Read-ReleaseProfile -Path $ConfigPath
    if ($null -eq $kernel) {
        Write-Host ('  ERROR: no existe ' + $ConfigPath) -ForegroundColor Red
        exit 1
    }

    $ok = Compare-ReleaseProfile -Label 'BAR/.cargo/config.toml' -Actual $kernel
    if ($ok) {
        Write-Host '  BAR/.cargo/config.toml: opt-level=3 - lto=true - codegen-units=1 - panic=abort' -ForegroundColor Green
    }

    # Busqueda del workspace contenedor (si lo hay).
    if (-not $WorkspaceRoot) {
        $dir = Get-Item -LiteralPath $RepoRoot
        while ($null -ne $dir.Parent) {
            $candidate = Join-Path $dir.Parent.FullName 'Cargo.toml'
            if (Test-Path -LiteralPath $candidate) {
                $text = Get-Content -LiteralPath $candidate -Raw
                if ($text -match '(?m)^\s*\[workspace\]') {
                    $WorkspaceRoot = $candidate
                    break
                }
            }
            $dir = $dir.Parent
        }
    }

    if ($WorkspaceRoot) {
        $resolved = (Resolve-Path -LiteralPath $WorkspaceRoot).Path
        $workspace = Read-ReleaseProfile -Path $resolved
        if ($null -eq $workspace) {
            Write-Host ('  ERROR: ' + $resolved + ' no declara [profile.release]') -ForegroundColor Red
            Write-Host '     Compilado desde esa raiz, el kernel perderia LTO, codegen-units=1 y panic=abort.' -ForegroundColor Red
            exit 1
        }
        $same = Compare-ReleaseProfile -Label $resolved -Actual $workspace
        if ($same) {
            Write-Host ('  ' + $resolved + ': identico') -ForegroundColor Green
        }
        $ok = $ok -and $same
    }
    else {
        Write-Host '  (sin workspace contenedor: solo se valida el perfil del kernel)' -ForegroundColor Yellow
    }

    Write-Host ''
    if ($ok) {
        Write-Host 'OK: los perfiles release son coherentes.' -ForegroundColor Green
        exit 0
    }
    Write-Host 'ERROR: los perfiles release han divergido.' -ForegroundColor Red
    exit 1
}
catch {
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Host ''
    Write-Host ('ERROR (linea ' + $line + '): ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
