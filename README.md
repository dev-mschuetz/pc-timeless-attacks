# TimelessAttack

A research harness for measuring HTTP/2 timeless timing attacks. The tool detects response-time asymmetries between two endpoints by coalescing paired HTTP/2 requests into a single TCP write, then recording which response arrives first across many trials. Statistical analysis (one-sided binomial test + Wilson score interval) determines whether the measured timing difference is significant.

## Background

Timeless timing attacks exploit the fact that when two requests share the same network packet, network jitter cancels out and the only remaining latency source is server-side processing time. This harness implements that technique over TLS + HTTP/2 on loopback or LAN, making it useful for controlled research into timing side-channels.

## Usage

Three modes are available: `server`, `client`, and `calibrate`.

### Server

```
timeless.exe -mode=server [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `127.0.0.1:8443` | Listen address |
| `-slow-us` | `0` | Microseconds of CPU burn on `/slow` (time-based, scheduler-sensitive) |
| `-slow-iter` | `0` | Fixed CPU iterations on `/slow` (overrides `-slow-us`, scheduler-free) |

The server exposes two endpoints:
- `/fast` — returns immediately
- `/slow` — burns CPU for the configured duration, then returns

### Client

Requires a server to be running. Sends paired HEADERS frames coalesced into one TCP write per trial and records which stream's response header arrives first.

```
timeless.exe -mode=client [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `127.0.0.1:8443` | Server address |
| `-trials` | `1000` | Number of paired trials |
| `-warmup` | `50` | Warmup trials discarded before counting |
| `-interleave` | `true` | Alternate which path gets the lower stream ID (cancels ordering bias) |
| `-timeout` | `10s` | Per-read timeout |
| `-progress` | `0` | Print a progress line every N trials (0 = silent) |
| `-v` | `false` | Verbose per-trial output |

### Calibrate

Measures how many CPU iterations correspond to a given nanosecond budget on the current hardware. Use this to pick a `-slow-iter` value targeting a specific delay.

```
timeless.exe -mode=calibrate
```

Prints a table mapping iteration counts to nanoseconds per call and estimates the OS timer resolution.

## Build

```bash
go build -o timeless.exe .
```

Requires Go 1.22+ and the `golang.org/x/net` module (resolved automatically via `go.sum`).

## Running an Experiment

### Step 1 — Calibrate (pick a `-slow-iter` value)

Run calibrate on the machine that will act as the server to find how many iterations map to your target delay:

```powershell
.\timeless.exe -mode=calibrate
```

Look at the `ns_per_call` column and pick an iteration count that matches your target burn time (e.g. 500 ns, 2 µs, 10 µs). Prefer `-slow-iter` over `-slow-us` — it doesn't call `time.Now()` so it is not affected by OS timer granularity.

### Step 2 — Quick manual test

In one terminal, start the server:

```powershell
.\timeless.exe -mode=server -slow-iter=1000
```

In a second terminal, run the client:

```powershell
.\timeless.exe -mode=client -trials=1000 -progress=100
```

Check the output: if `/fast` wins significantly more than 50 % of trials and the p-value is well below 0.05, the timing asymmetry is detectable.

### Step 3 — Automated sweep

Use `run-experiment.ps1` to sweep across multiple delay values in one shot. It starts a fresh server per data point, saves raw output, and writes a summary CSV.

```powershell
# Iteration-mode sweep (recommended — scheduler-free)
# Values chosen from calibration: 1000->835ns, 3000->2.5us, 10000->12.6us, 30000->40us
.\run-experiment.ps1 -SlowIterValues 0,1000,3000,10000,30000 -Trials 1000

# Microsecond-mode sweep (coarser, scheduler-sensitive)
.\run-experiment.ps1 -SlowUsValues 0,1,2,5,10,20,50,100 -Trials 1000

# More trials for tighter confidence intervals
.\run-experiment.ps1 -SlowIterValues 0,1000,3000,10000,30000 -Trials 3000
```

Results are written to `results/results.csv` and per-run logs to `results/raw/`.

### Recommended workflow

1. Run calibrate to map your hardware's iteration speed.
2. Do a quick manual test at a large delay (e.g. `-slow-iter=30000`) to confirm the setup works end-to-end.
3. Run a sweep starting from the largest delay and ratchet down toward your noise floor — the point where the signal disappears is your detection threshold.

## Automated Experiment Sweeps

`run-experiment.ps1` orchestrates multi-point sweeps. It starts a fresh server instance per data point, runs the client, parses output, and appends a row to `results/results.csv`. Raw client stdout is saved under `results/raw/`.

```powershell
# Default sweep over a built-in iteration range, 1000 trials each
.\run-experiment.ps1

# Custom iteration values, more trials
.\run-experiment.ps1 -SlowIterValues 0,1000,3000,10000,30000 -Trials 3000

# Microsecond mode
.\run-experiment.ps1 -SlowUsValues 0,1,2,5,10,20,50,100
```

Results CSV columns:

```
mode, slow_value, trials, fast_wins, fast_win_pct,
fast_first_pos_pct, fast_second_pos_pct,
p_value, wilson_lo, wilson_hi, duration_sec
```

## Output Interpretation

```
trials:              3000
fast arrived first:  1911 (63.70%)
  when fast sent 1st: 1861/1500 (…)
  when fast sent 2nd: 50/1500  (…)
one-sided p-value:   1.02e-51
Wilson 95% CI:       [0.619, 0.655]
```

- **fast arrived first** — fraction of trials where `/fast`'s response header beat `/slow`'s. Should be ~50% under the null (no timing difference).
- **position-conditional rates** — win rate split by which path held the lower stream ID. A large spread here indicates ordering bias; `-interleave` is designed to cancel it.
- **p-value** — one-sided binomial test against H0: p = 0.5. Values well below 0.05 indicate a detectable timing difference.
- **Wilson 95% CI** — confidence interval on the true win probability.

## Statistical Methods

- **Binomial test** — implemented in log-space to handle large trial counts without underflow (`oneSidedBinomialPValue`).
- **Wilson score interval** — preferred over the normal approximation for small or extreme probabilities (`wilsonCI`).

## Project Structure

```
server.go              # Server, calibrate mode, TLS cert generation, flags, main
client.go              # Client, H2 dial, statistical analysis
run-experiment.ps1     # PowerShell sweep harness
go.mod / go.sum        # Module definition (module: trial, Go 1.26.2)
timeless.exe           # Pre-built Windows binary
results/
  results.csv          # Aggregated sweep output
  raw/                 # Per-data-point raw client stdout and server logs
```

## Dependencies

| Module | Version | Purpose |
|--------|---------|---------|
| `golang.org/x/net` | v0.53.0 | HTTP/2 framing and HPACK |
| `golang.org/x/text` | v0.36.0 | Transitive dependency |

## Limitations and Notes

- The self-signed TLS certificate is generated in-memory at server startup; the client skips verification (`InsecureSkipVerify`).
- Time-based burn (`-slow-us`) is sensitive to OS scheduler preemption and timer resolution. On Windows, timer granularity is typically 100 ns – 1 µs; prefer `-slow-iter` for reproducible experiments.
- Results are most reliable over loopback (127.0.0.1), where network jitter is minimal and coalescing is guaranteed.
