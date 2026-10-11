<#
.SYNOPSIS
    Estado de la ultima ejecucion de CI del repositorio Bara (AETHER-Omega).
.DESCRIPTION
    Consulta la API de GitHub y resume las ejecuciones recientes de CI de una
    rama: numero de run, conclusion global y el estado de cada job. El token
    nunca se imprime ni se escribe en disco.
.PARAMETER Branch
    Rama a inspeccionar (por defecto: dev).
.PARAMETER Runs
    Numero de ejecuciones recientes a listar (por defecto: 3).
.EXAMPLE
    ./scripts/ci_status.ps1
    ./scripts/ci_status.ps1 -Branch main -Runs 5
.NOTES
    Orden de resolucion de la credencial: GH_TOKEN, GITHUB_TOKEN,
    'gh auth token' y, como ultimo recurso, 'git credential fill'.
    Ruta oficial versionada: scripts/ci_status.ps1
#>
[CmdletBinding()]
param(
    [string]$Branch = 'dev',
    [int]$Runs = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo = 'usercardjoke1036991-star/Bara-AETHER--Engine-Final-Expansion'
$Api = 'https://api.github.com/repos/' + $Repo

# Devuelve un token de GitHub sin exponerlo en la salida.
function Get-GitHubToken {
    if ($env:GH_TOKEN) { return $env:GH_TOKEN }
    if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }

    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($gh) {
        try {
            $token = (& $gh.Source auth token 2>$null)
            if ($LASTEXITCODE -eq 0 -and $token) { return $token.Trim() }
        }
        catch {
            Write-Verbose 'gh auth token no disponible; se probara con git.'
        }
    }

    try {
        $filled = ("protocol=https`nhost=github.com`n`n" | git credential fill) 2>$null
        $line = $filled | Where-Object { $_ -like 'password=*' } | Select-Object -First 1
        if ($line) { return ($line -replace '^password=', '').Trim() }
    }
    catch {
        Write-Verbose 'git credential fill no disponible.'
    }

    throw 'Sin credencial de GitHub: define GH_TOKEN o ejecuta gh auth login.'
}

# GET a la API con el diagnostico completo del error de GitHub.
function Get-ApiJson {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    try {
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
    }
    catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $detail = $detail + ' :: ' + $_.ErrorDetails.Message
        }
        throw $detail
    }
}

$token = $null
$headers = $null

try {
    $token = Get-GitHubToken
    $headers = @{
        Authorization = 'Bearer ' + $token
        Accept        = 'application/vnd.github+json'
        'User-Agent'  = 'bara-ci-status'
    }

    Write-Host ('Bara (AETHER-Omega) - CI de la rama ' + $Branch) -ForegroundColor Cyan
    Write-Host ('Repositorio: ' + $Repo)

    # Ojo: los nombres de variable de PowerShell NO distinguen mayusculas, asi
    # que `$runs` seria el MISMO objeto que el parametro [int]$Runs y la
    # asignacion intentaria convertir el JSON a entero. De ahi `$runsPage`.
    $runsPage = Get-ApiJson -Uri ($Api + '/actions/runs?branch=' + $Branch + '&per_page=' + $Runs) -Headers $headers

    if ($runsPage.total_count -eq 0) {
        Write-Host 'Sin ejecuciones registradas para esa rama.' -ForegroundColor Yellow
    }
    else {
        foreach ($run in $runsPage.workflow_runs) {
            $conclusion = if ($run.conclusion) { $run.conclusion } else { $run.status }
            $color = switch ($conclusion) {
                'success' { 'Green' }
                'failure' { 'Red' }
                'cancelled' { 'DarkYellow' }
                default { 'Gray' }
            }
            $sha = $run.head_sha.Substring(0, 7)
            Write-Host ('  #' + $run.run_number + '  ' + $conclusion.ToUpper() + '  ' + $run.head_branch + '  ' + $sha) -ForegroundColor $color

            $jobsPage = Get-ApiJson -Uri ($Api + '/actions/runs/' + $run.id + '/jobs') -Headers $headers
            foreach ($job in $jobsPage.jobs) {
                $state = if ($job.conclusion) { $job.conclusion } else { $job.status }
                Write-Host ('      job: ' + $job.name + ' -> ' + $state)
            }
        }
    }

    Write-Host ''
    Write-Host 'OK: consulta completada.' -ForegroundColor Green
    exit 0
}
catch {
    $line = $_.InvocationInfo.ScriptLineNumber
    $source = $_.InvocationInfo.Line
    Write-Host ''
    Write-Host ('ERROR (linea ' + $line + '): ' + $_.Exception.Message) -ForegroundColor Red
    if ($source) { Write-Host ('  ' + $source.Trim()) -ForegroundColor DarkGray }
    exit 1
}
finally {
    $token = $null
    $headers = $null
}
