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
    [int[]] $SlowUsValues   = @(0, 1, 2, 5, 10, 20, 50, 100),
    [int[]] $SlowIterValues = @(),  # if non-empty, use iteration mode instead of µs
    [int[]] $NsValues       = @(),  # optional: ns_per_call for each point (from -mode=calibrate), shown in summary
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

if (-not (Test-Path "go.mod")) {
    Write-Error "go.mod not found - run this script from the project root."
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "raw") | Out-Null

# Build the binary once up front. Using `go run` from the script spawns a
# child binary whose PID we can't reliably track, which leaves orphan
# listeners on Windows. Building once gives us one PID per server.
$binary = Join-Path (Get-Location) "timeless.exe"
Write-Host "Building $binary ..." -ForegroundColor Cyan
& go build -o $binary .
if ($LASTEXITCODE -ne 0) {
    Write-Error "go build failed."
    exit 1
}

$csvPath = Join-Path $OutDir "results.csv"
"mode,slow_value,trials,fast_wins,fast_win_pct,fast_first_pos_pct,fast_second_pos_pct,p_value,wilson_lo,wilson_hi,duration_sec" |
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
        [int] $SlowValue,
        [string] $Mode,  # "us" or "iter"
        [int] $Port
    )

    $addr = "127.0.0.1:$Port"
    $tag = if ($Mode -eq "iter") { "iter_${SlowValue}" } else { "slow_${SlowValue}us" }
    $rawPath = Join-Path (Join-Path $OutDir "raw") "${tag}.txt"

    Write-Host "--- $Mode=$SlowValue on $addr ---" -ForegroundColor Yellow

    $serverLog = Join-Path (Join-Path $OutDir "raw") "server_${tag}.log"
    $serverArgs = if ($Mode -eq "iter") {
        @("-mode=server", "-slow-iter=$SlowValue", "-addr=$addr")
    } else {
        @("-mode=server", "-slow-us=$SlowValue", "-addr=$addr")
    }
    $serverProc = Start-Process `
        -FilePath $binary `
        -ArgumentList $serverArgs `
        -RedirectStandardError $serverLog `
        -RedirectStandardOutput "$serverLog.out" `
        -NoNewWindow `
        -PassThru

    # Wait for the server to actually be listening, up to 5 seconds.
    $ready = $false
    for ($try = 0; $try -lt 50; $try++) {
        Start-Sleep -Milliseconds 100
        if ($serverProc.HasExited) { break }
        $probe = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($probe) { $ready = $true; break }
    }
    if (-not $ready) {
        Write-Warning "Server never bound to port $Port. See $serverLog"
        Get-Content $serverLog -ErrorAction SilentlyContinue | Write-Host
        try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
        return $null
    }

    $startTime = Get-Date
    $clientOut = & $binary -mode=client "-addr=$addr" "-trials=$Trials" "-warmup=$Warmup" "-progress=0" 2>&1 | Out-String
    $duration = (Get-Date) - $startTime

    # Save full client output for audit.
    $clientOut | Out-File -FilePath $rawPath -Encoding utf8

    # Clean kill via real PID.
    try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    # Belt and suspenders: also kill anything still listening on our port.
    try {
        $owning = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($procId in $owning) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
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
        mode = $Mode
        slow_value = $SlowValue
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
        Write-Warning "Could not parse client output for $Mode=$SlowValue. See $rawPath"
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
        $parsed.mode, $parsed.slow_value, $parsed.trials, $parsed.fast_wins, $parsed.fast_win_pct,
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
$sweepStart = Get-Date

if ($SlowIterValues.Count -gt 0) {
    Write-Host "Running iter-mode sweep (fixed iteration counts, scheduler-free)" -ForegroundColor Cyan
    foreach ($iter in $SlowIterValues) {
        $result = Run-OnePoint -SlowValue $iter -Mode "iter" -Port $port
        if ($result) { $allResults += $result }
        $port++
    }
} else {
    Write-Host "Running us-mode sweep (time-based, scheduler-sensitive)" -ForegroundColor Cyan
    foreach ($slowUs in $SlowUsValues) {
        $result = Run-OnePoint -SlowValue $slowUs -Mode "us" -Port $port
        if ($result) { $allResults += $result }
        $port++
    }
}

# --------------------------------------------------------------------------
# Final summary table
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$colLabel = if ($SlowIterValues.Count -gt 0) { "iter" } else { "slow_us" }
$showNs = $NsValues.Count -gt 0
if ($showNs) {
    Write-Host ("{0,-10} {1,-10} {2,-10} {3,-12} {4,-12} {5,-12}" -f $colLabel, "delay", "overall%", "1st-pos%", "2nd-pos%", "p-value")
    Write-Host ("{0,-10} {1,-10} {2,-10} {3,-12} {4,-12} {5,-12}" -f "-------", "-----", "--------", "--------", "--------", "-------")
} else {
    Write-Host ("{0,-10} {1,-10} {2,-12} {3,-12} {4,-12}" -f $colLabel, "overall%", "1st-pos%", "2nd-pos%", "p-value")
    Write-Host ("{0,-10} {1,-10} {2,-12} {3,-12} {4,-12}" -f "-------", "--------", "--------", "--------", "-------")
}
$idx = 0
foreach ($r in $allResults) {
    if ($showNs -and $idx -lt $NsValues.Count) {
        $ns = $NsValues[$idx]
        $delayStr = if ($ns -ge 1000) { "$([math]::Round($ns/1000, 1))us" } else { "${ns}ns" }
        Write-Host ("{0,-10} {1,-10} {2,-10} {3,-12} {4,-12} {5,-12}" -f
            $r.slow_value, $delayStr, $r.fast_win_pct, $r.fast_first_pos_pct, $r.fast_second_pos_pct, $r.p_value)
    } else {
        Write-Host ("{0,-10} {1,-10} {2,-12} {3,-12} {4,-12}" -f
            $r.slow_value, $r.fast_win_pct, $r.fast_first_pos_pct, $r.fast_second_pos_pct, $r.p_value)
    }
    $idx++
}
Write-Host ""
Write-Host "CSV: $csvPath" -ForegroundColor Cyan
Write-Host "Per-run logs: $(Join-Path $OutDir 'raw')" -ForegroundColor Cyan
