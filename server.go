// Timeless Timing Attack — H2 Lab Harness
//
// A self-contained Go program that runs BOTH sides of a timeless-timing
// experiment against an HTTP/2 server you control. Intended for authorized
// testing on your own infrastructure only.
//
// Usage:
//   go run server.go client.go -mode=server
//   go run server.go client.go -mode=client -trials=1000
//
// What it does:
//   - Server: TLS+H2 with /fast and /slow endpoints. /slow burns a
//     configurable number of microseconds of CPU to create a known
//     ground-truth asymmetry.
//   - Client: Opens one H2 connection, sends paired HEADERS frames for
//     /fast and /slow coalesced into a single Write() (and usually a single
//     TCP segment on loopback/LAN). Reads response HEADERS frames back and
//     records which stream ID arrived first.
//   - Analysis: One-sided binomial test on the arrival-order distribution.
//     Under H0 (no timing difference), P(fast first) = 0.5. If /slow
//     genuinely takes longer, /fast should win more often.
//
// Dependencies:
//   go get golang.org/x/net/http2
//   go get golang.org/x/net/http2/hpack
//
// Start with -slow-us=50 on loopback. Once you see a clean signal, ratchet
// it down toward your stack's noise floor.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"golang.org/x/net/http2"
)

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

var (
	mode       = flag.String("mode", "", "server | client | calibrate")
	addr       = flag.String("addr", "127.0.0.1:8443", "listen/connect address")
	slowUs     = flag.Int("slow-us", 0, "microseconds of CPU work for /slow (time-based, coarse, scheduler-sensitive)")
	slowIter   = flag.Int("slow-iter", 0, "fixed iterations of inner mixing loop for /slow (fine-grained, scheduler-free). If >0, overrides -slow-us.")
	trials     = flag.Int("trials", 1000, "client: number of paired probes")
	warmup     = flag.Int("warmup", 50, "client: warmup probes discarded from analysis")
	interleave = flag.Bool("interleave", true, "client: swap stream order every other trial to cancel fixed bias")
	verbose    = flag.Bool("v", false, "verbose per-trial output")
	progress   = flag.Int("progress", 0, "client: print progress every N trials (0 = off)")
	timeout    = flag.Duration("timeout", 10*time.Second, "client: per-read timeout on the H2 connection")
)

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()
	switch *mode {
	case "server":
		runServer()
	case "client":
		runClient()
	case "calibrate":
		runCalibrate()
	default:
		fmt.Fprintln(os.Stderr, "usage: timeless -mode=server | -mode=client | -mode=calibrate [flags]")
		os.Exit(2)
	}
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

func runServer() {
	cert, key := selfSignedCert()
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("tls keypair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/fast", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		io.WriteString(w, "fast\n")
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		if *slowIter > 0 {
			burnIter(*slowIter)
		} else if *slowUs > 0 {
			burnCPU(time.Duration(*slowUs) * time.Microsecond)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		io.WriteString(w, "slow\n")
	})

	srv := &http.Server{
		Addr:      *addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{"h2"}},
		ErrorLog:  log.New(os.Stderr, "h2-server: ", log.LstdFlags),
	}
	// Force H2 only; rejects HTTP/1.1 clients so we don't accidentally measure
	// the wrong protocol.
	h2s := &http2.Server{}
	if err := http2.ConfigureServer(srv, h2s); err != nil {
		log.Fatalf("configure h2: %v", err)
	}

	if *slowIter > 0 {
		log.Printf("server listening on https://%s (slow=%d iter)", *addr, *slowIter)
	} else {
		log.Printf("server listening on https://%s (slow=%dµs)", *addr, *slowUs)
	}
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// burnCPU spins for approximately d, doing non-optimizable work so the
// compiler doesn't elide it. This models a handler that takes longer
// because of some secret-dependent computation.
//
// LIMITATIONS: Uses time.Now() which has ~100ns-1µs resolution on Windows
// and significant per-call overhead. Not suitable for sub-microsecond burn
// targets. For fine-grained work, use burnIter instead.
func burnCPU(d time.Duration) {
	deadline := time.Now().Add(d)
	var x uint64 = 1
	for time.Now().Before(deadline) {
		for i := 0; i < 1000; i++ {
			x = x*6364136223846793005 + 1442695040888963407
		}
	}
	sink = x
}

// burnIter does exactly n iterations of the mixing loop. No time.Now()
// calls, no scheduler interaction (as long as n is small enough that we
// don't get preempted). Calibrate with -mode=calibrate to map iterations
// to wall-clock nanoseconds on your hardware.
func burnIter(n int) {
	var x uint64 = 1
	for i := 0; i < n; i++ {
		x = x*6364136223846793005 + 1442695040888963407
	}
	sink = x
}

var sink uint64

// ---------------------------------------------------------------------------
// Calibrate (maps -slow-iter values to wall-clock nanoseconds)
// ---------------------------------------------------------------------------

// runCalibrate times burnIter at a range of iteration counts so you can
// pick a sensible -slow-iter value for a target nanosecond budget. It
// times BATCHES of calls to get enough elapsed time that timer resolution
// isn't the limiting factor — Windows' time.Now() can have ~1ms
// granularity, which would round small single-call measurements to zero.
func runCalibrate() {
	iterCounts := []int{10, 30, 100, 300, 1000, 3000, 10000, 30000, 100000}
	// Target ~50ms of measured time per batch so we get many timer ticks
	// regardless of OS timer granularity.
	const targetBatchDuration = 50 * time.Millisecond
	const numBatches = 21

	// First, measure timer granularity on this machine so we can report it.
	timerRes := measureTimerResolution()
	if timerRes == 0 {
		fmt.Println("timer resolution on this machine: >200ms (could not observe a tick)")
	} else {
		fmt.Printf("timer resolution on this machine: ~%dns\n", timerRes.Nanoseconds())
	}
	fmt.Println("calibrating burnIter ...")
	fmt.Printf("%-10s %-14s %-14s %-14s %-10s\n", "iters", "ns_per_call", "p10_ns", "p90_ns", "batch_size")

	for _, n := range iterCounts {
		// Warm up
		for i := 0; i < 10; i++ {
			burnIter(n)
		}

		// Probe batch size: do a rough timing pass to pick how many calls
		// per batch gets us to ~targetBatchDuration.
		probeStart := time.Now()
		const probeCalls = 100
		for i := 0; i < probeCalls; i++ {
			burnIter(n)
		}
		probeElapsed := time.Since(probeStart)
		var batchSize int
		if probeElapsed < time.Microsecond {
			// Very fast — use a large batch
			batchSize = 1_000_000
		} else {
			batchSize = int(float64(probeCalls) * float64(targetBatchDuration) / float64(probeElapsed))
			if batchSize < 100 {
				batchSize = 100
			}
			if batchSize > 10_000_000 {
				batchSize = 10_000_000
			}
		}

		// Now real measurements
		samples := make([]time.Duration, numBatches)
		for b := 0; b < numBatches; b++ {
			t0 := time.Now()
			for i := 0; i < batchSize; i++ {
				burnIter(n)
			}
			samples[b] = time.Since(t0)
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		med := samples[numBatches/2]
		p10 := samples[numBatches/10]
		p90 := samples[numBatches-numBatches/10-1]
		// ns per single call
		nsPerCall := med.Nanoseconds() / int64(batchSize)
		p10Ns := p10.Nanoseconds() / int64(batchSize)
		p90Ns := p90.Nanoseconds() / int64(batchSize)
		fmt.Printf("%-10d %-14d %-14d %-14d %-10d\n", n, nsPerCall, p10Ns, p90Ns, batchSize)
	}
	fmt.Println()
	fmt.Println("Use ns_per_call to pick -slow-iter for a target burn time:")
	fmt.Println("  target 500ns  → pick iters where ns_per_call ≈ 500")
	fmt.Println("  target 2µs    → pick iters where ns_per_call ≈ 2000")
	fmt.Println("  target 10µs   → pick iters where ns_per_call ≈ 10000")
}

// measureTimerResolution estimates the OS timer granularity by spinning until
// time.Now() advances, then returning that first observed step. Bounded to
// 200ms so it doesn't hang on pathological systems.
func measureTimerResolution() time.Duration {
	deadline := time.Now().Add(200 * time.Millisecond)
	prev := time.Now()
	for time.Now().Before(deadline) {
		now := time.Now()
		if d := now.Sub(prev); d > 0 {
			return d
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Self-signed TLS cert (in-memory, fresh every server start)
// ---------------------------------------------------------------------------

func selfSignedCert() (certPEM, keyPEM []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("gen key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "timeless-lab"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
