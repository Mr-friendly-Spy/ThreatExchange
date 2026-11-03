# Run from PowerShell; pass ordinary Docker arguments, e.g. .\scripts\docker.ps1 compose ps.
# Prefer Docker Desktop when available; otherwise use Docker Engine in Ubuntu/WSL 2.
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$keeperFile = Join-Path $projectRoot '.tmp\wsl-keeper.json'

function Get-WorkspaceKeeper {
    if (-not (Test-Path -LiteralPath $keeperFile)) { return $null }
    $saved = Get-Content -LiteralPath $keeperFile -Raw | ConvertFrom-Json
    $candidate = Get-Process -Id $saved.ProcessId -ErrorAction SilentlyContinue
    # Match both identity and creation time; never stop a reused process ID.
    if ($candidate -and $candidate.ProcessName -eq 'wsl' -and
        $candidate.StartTime.ToUniversalTime().Ticks -eq $saved.StartTicks) {
        return $candidate
    }
    return $null
}

function Stop-WorkspaceKeeper {
    $keeper = Get-WorkspaceKeeper
    if ($keeper) {
        # wsl.exe can launch a second Windows process; stop the validated owned tree.
        & taskkill.exe /PID $keeper.Id /T /F | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not stop the workspace WSL keeper.' }
    }
    if (Test-Path -LiteralPath $keeperFile) { Remove-Item -LiteralPath $keeperFile }
}

$dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
if ($dockerCommand) {
    Push-Location -LiteralPath $projectRoot
    try {
        & $dockerCommand.Source @args
        $dockerExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    exit $dockerExitCode
}
$managedProject = ($args -contains 'compose') -and ($args -contains 'threat-exchange')
$createdKeeper = $false
if ($managedProject -and ($args -contains 'up') -and -not (Get-WorkspaceKeeper)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $keeperFile) | Out-Null
    $keeper = Start-Process -FilePath wsl.exe -ArgumentList '-d','Ubuntu','--exec','sleep','infinity' -WindowStyle Hidden -PassThru
    @{ ProcessId = $keeper.Id; StartTicks = $keeper.StartTime.ToUniversalTime().Ticks } |
        ConvertTo-Json | Set-Content -LiteralPath $keeperFile -Encoding UTF8
    $createdKeeper = $true
}
& wsl.exe -d Ubuntu -u root --cd $projectRoot -- docker @args
$dockerExitCode = $LASTEXITCODE
if (($managedProject -and ($args -contains 'down') -and $dockerExitCode -eq 0) -or
    ($createdKeeper -and $dockerExitCode -ne 0)) {
    Stop-WorkspaceKeeper
}
exit $dockerExitCode
