# run-experiment.ps1
#
# Sweeps the /slow endpoint's artificial compute asymmetry across a range of
# values, runs the client against each, and captures results to CSV.
#
# Usage:
#   .\run-experiment.ps1                        # default sweep
#   .\run-experiment.ps1 -Trials 2000           # more trials per point
#   .\run-experiment.ps1 -SlowUsValues 0,5,10   # custom sweep
#
# Outputs:
#   results.csv  — one row per slow-us value
#   raw/         — full client stdout for each run, for auditing
#
# The server is started fresh on a new port for each data point so we don't
# hit TIME_WAIT / "address in use" between runs.

[CmdletBinding()]
param(
    [int[]] $SlowUsValues = @(0, 1, 2, 5, 10, 20, 50, 100),
    [int]   $Trials       = 1000,
    [int]   $Warmup       = 50,
    [int]   $StartPort    = 18400,
    [string] $OutDir      = "results",
    [int]   $ServerBootSec = 2,
    [int]   $BetweenRunsSec = 1
)

$ErrorActionPreference = "Stop"

# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------

if (-not (Test-Path "timeless.go")) {
    Write-Error "timeless.go not found in current directory."
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "raw") | Out-Null

$csvPath = Join-Path $OutDir "results.csv"
"slow_us,trials,fast_wins,fast_win_pct,fast_first_pos_pct,fast_second_pos_pct,p_value,wilson_lo,wilson_hi,duration_sec" |
    Out-File -FilePath $csvPath -Encoding utf8

Write-Host "=== Timeless Timing Sweep ===" -ForegroundColor Cyan
Write-Host "Sweep points : $($SlowUsValues -join ', ') µs"
Write-Host "Trials/point : $Trials (+ $Warmup warmup)"
Write-Host "Output       : $csvPath"
Write-Host ""

# --------------------------------------------------------------------------
# Per-point runner
# --------------------------------------------------------------------------

function Run-OnePoint {
    param(
        [int] $SlowUs,
        [int] $Port
    )

    $addr = "127.0.0.1:$Port"
    $rawPath = Join-Path (Join-Path $OutDir "raw") "slow_${SlowUs}us.txt"

    Write-Host "--- slow-us=$SlowUs on $addr ---" -ForegroundColor Yellow

    # Start server in background. We capture its stderr to the raw folder
    # in case we need to debug a bad run.
    $serverLog = Join-Path (Join-Path $OutDir "raw") "server_slow_${SlowUs}us.log"
    $serverProc = Start-Process `
        -FilePath "go" `
        -ArgumentList @("run", "timeless.go", "-mode=server", "-slow-us=$SlowUs", "-addr=$addr") `
        -RedirectStandardError $serverLog `
        -RedirectStandardOutput "$serverLog.out" `
        -NoNewWindow `
        -PassThru

    # Give the server time to bind. `go run` needs to compile first.
    Start-Sleep -Seconds $ServerBootSec

    if ($serverProc.HasExited) {
        Write-Warning "Server exited immediately. See $serverLog"
        Get-Content $serverLog -ErrorAction SilentlyContinue | Write-Host
        return $null
    }

    $startTime = Get-Date
    $clientOut = & go run timeless.go -mode=client "-addr=$addr" "-trials=$Trials" "-warmup=$Warmup" "-progress=0" 2>&1 | Out-String
    $duration = (Get-Date) - $startTime

    # Save full client output for audit.
    $clientOut | Out-File -FilePath $rawPath -Encoding utf8

    # Stop the server. Start-Process doesn't give us child PIDs cleanly on
    # Windows because `go run` spawns a child binary, so we kill the whole
    # process tree by image name+port. Safer: kill by PID and also whatever
    # is listening on the port.
    try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    try {
        $owning = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($pid in $owning) {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    Start-Sleep -Seconds $BetweenRunsSec

    # --------------------------------------------------------------------
    # Parse client output.
    # Expected lines:
    #   trials:              1000
    #   fast arrived first:  873 (87.30%)
    #     when fast sent 1st: 495/500 (99.00%)
    #     when fast sent 2nd: 378/500 (75.60%)
    #   one-sided p-value:   1.23e-45  (H0: no timing difference)
    #   Wilson 95% CI:       [0.852, 0.891]
    # --------------------------------------------------------------------

    $parsed = @{
        slow_us = $SlowUs
        trials = $null
        fast_wins = $null
        fast_win_pct = $null
        fast_first_pos_pct = $null
        fast_second_pos_pct = $null
        p_value = $null
        wilson_lo = $null
        wilson_hi = $null
        duration_sec = [math]::Round($duration.TotalSeconds, 2)
    }

    foreach ($line in $clientOut -split "`r?`n") {
        if ($line -match '^trials:\s+(\d+)') {
            $parsed.trials = [int]$Matches[1]
        }
        elseif ($line -match '^fast arrived first:\s+(\d+)\s+\(([\d.]+)%\)') {
            $parsed.fast_wins = [int]$Matches[1]
            $parsed.fast_win_pct = [double]$Matches[2]
        }
        elseif ($line -match 'when fast sent 1st:\s+\d+/\d+\s+\(([\d.]+)%\)') {
            $parsed.fast_first_pos_pct = [double]$Matches[1]
        }
        elseif ($line -match 'when fast sent 2nd:\s+\d+/\d+\s+\(([\d.]+)%\)') {
            $parsed.fast_second_pos_pct = [double]$Matches[1]
        }
        elseif ($line -match 'one-sided p-value:\s+(\S+)') {
            $parsed.p_value = $Matches[1]
        }
        elseif ($line -match 'Wilson 95% CI:\s+\[([\d.]+),\s*([\d.]+)\]') {
            $parsed.wilson_lo = [double]$Matches[1]
            $parsed.wilson_hi = [double]$Matches[2]
        }
    }

    if ($null -eq $parsed.trials) {
        Write-Warning "Could not parse client output for slow-us=$SlowUs. See $rawPath"
        Write-Host $clientOut
        return $null
    }

    # Pretty-print summary to console.
    $posNote = ""
    if ($parsed.fast_first_pos_pct -ne $null -and $parsed.fast_second_pos_pct -ne $null) {
        $posNote = "  (1st-pos: $($parsed.fast_first_pos_pct)%, 2nd-pos: $($parsed.fast_second_pos_pct)%)"
    }
    Write-Host ("  overall: {0}% fast-wins in {1}s{2}" -f
        $parsed.fast_win_pct, $parsed.duration_sec, $posNote) -ForegroundColor Green

    # Append to CSV.
    $row = @(
        $parsed.slow_us, $parsed.trials, $parsed.fast_wins, $parsed.fast_win_pct,
        $parsed.fast_first_pos_pct, $parsed.fast_second_pos_pct, $parsed.p_value,
        $parsed.wilson_lo, $parsed.wilson_hi, $parsed.duration_sec
    ) -join ","
    $row | Out-File -FilePath $csvPath -Encoding utf8 -Append

    return $parsed
}

# --------------------------------------------------------------------------
# Main sweep
# --------------------------------------------------------------------------

$allResults = @()
$port = $StartPort
foreach ($slowUs in $SlowUsValues) {
    $result = Run-OnePoint -SlowUs $slowUs -Port $port
    if ($result) { $allResults += $result }
    $port++
}

# --------------------------------------------------------------------------
# Final summary table
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("{0,-8} {1,-10} {2,-12} {3,-12} {4,-12}" -f "slow_us", "overall%", "1st-pos%", "2nd-pos%", "p-value")
Write-Host ("{0,-8} {1,-10} {2,-12} {3,-12} {4,-12}" -f "-------", "--------", "--------", "--------", "-------")
foreach ($r in $allResults) {
    Write-Host ("{0,-8} {1,-10} {2,-12} {3,-12} {4,-12}" -f
        $r.slow_us, $r.fast_win_pct, $r.fast_first_pos_pct, $r.fast_second_pos_pct, $r.p_value)
}
Write-Host ""
Write-Host "CSV: $csvPath" -ForegroundColor Cyan
Write-Host "Per-run logs: $(Join-Path $OutDir 'raw')" -ForegroundColor Cyan
