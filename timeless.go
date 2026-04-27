// Timeless Timing Attack — H2 Lab Harness
//
// A self-contained Go program that runs BOTH sides of a timeless-timing
// experiment against an HTTP/2 server you control. Intended for authorized
// testing on your own infrastructure only.
//
// Usage:
//   go run timeless.go -mode=server
//   go run timeless.go -mode=client -trials=1000
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
	"bufio"
	"bytes"
	"context"
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
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
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
	fmt.Printf("timer resolution on this machine: ~%dns (from 1000 successive time.Now() calls)\n", timerRes.Nanoseconds())
	fmt.Println("calibrating burnIter ...")
	fmt.Printf("%-10s %-14s %-14s %-14s %-10s\n", "iters", "ns_per_call", "p10_ns", "p90_ns", "batch_size")

	for _, n := range iterCounts {
		// Warm up.
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
			// Very fast — use a large batch.
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

		// Now the real measurements.
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
		// ns per single call.
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

// measureTimerResolution estimates the OS timer granularity by sampling
// time.Now() in a tight loop and finding the smallest non-zero gap.
func measureTimerResolution() time.Duration {
	const samples = 10000
	min := time.Hour
	prev := time.Now()
	for i := 0; i < samples; i++ {
		now := time.Now()
		d := now.Sub(prev)
		if d > 0 && d < min {
			min = d
		}
		prev = now
	}
	return min
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type trialResult struct {
	firstStreamID uint32 // stream ID of the first HEADERS frame we saw
	fastStreamID  uint32
	slowStreamID  uint32
}

func (r trialResult) fastWon() bool { return r.firstStreamID == r.fastStreamID }

func runClient() {
	conn, bw, framer, err := dialH2(*addr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Shared HPACK encoder. Using one encoder across trials means the second
	// probe in each pair gets smaller headers (indexed), which is fine —
	// what matters is that /fast and /slow have symmetric header sizes,
	// which they do (same method, same authority, same scheme, paths differ
	// only in the last four bytes).
	var hbuf bytes.Buffer
	henc := hpack.NewEncoder(&hbuf)

	encodeHeaders := func(path string) []byte {
		hbuf.Reset()
		henc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		henc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		henc.WriteField(hpack.HeaderField{Name: ":authority", Value: *addr})
		henc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
		henc.WriteField(hpack.HeaderField{Name: "accept", Value: "*/*"})
		// Copy because hbuf is reused on the next call.
		out := make([]byte, hbuf.Len())
		copy(out, hbuf.Bytes())
		return out
	}

	results := make([]trialResult, 0, *trials)
	total := *trials + *warmup
	nextStreamID := uint32(1) // client streams are odd

	for i := 0; i < total; i++ {
		// Alternate which path gets the lower stream ID, to cancel any
		// fixed bias the server might have toward processing the lower
		// stream ID first. We ALWAYS send the lower stream ID first on
		// the wire — H2 requires strictly-increasing client stream IDs,
		// and reordering them is a PROTOCOL_ERROR.
		firstID := nextStreamID
		secondID := nextStreamID + 2
		nextStreamID += 4

		var fastID, slowID uint32
		var firstPath, secondPath string
		if *interleave && i%2 == 1 {
			// This trial: /slow gets the lower ID.
			slowID, fastID = firstID, secondID
			firstPath, secondPath = "/slow", "/fast"
		} else {
			// This trial: /fast gets the lower ID.
			fastID, slowID = firstID, secondID
			firstPath, secondPath = "/fast", "/slow"
		}

		// Encode both header blocks up front so both WriteHeaders calls are
		// back-to-back with no computation between them.
		firstBlock := encodeHeaders(firstPath)
		secondBlock := encodeHeaders(secondPath)

		// Write both HEADERS frames into the bufio.Writer, then one Flush.
		// The Flush issues a single Write() to the kernel, which on
		// loopback/LAN lands in a single TCP segment.
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      firstID,
			BlockFragment: firstBlock,
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			log.Fatalf("write first headers: %v", err)
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      secondID,
			BlockFragment: secondBlock,
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			log.Fatalf("write second headers: %v", err)
		}
		if err := bw.Flush(); err != nil {
			log.Fatalf("flush: %v", err)
		}

		// Per-trial deadline. If something goes wrong on one trial we want
		// to abort that trial and see progress, not hang forever.
		conn.SetReadDeadline(time.Now().Add(*timeout))

		// Read frames until both streams have reached END_STREAM. HEADERS
		// and DATA frames for the two streams can interleave arbitrarily
		// on the wire, so we track both streams' progress in parallel
		// rather than trying to drain them sequentially.
		res := trialResult{fastStreamID: fastID, slowStreamID: slowID}
		headersSeen := map[uint32]bool{fastID: false, slowID: false}
		streamEnded := map[uint32]bool{fastID: false, slowID: false}
		for !(streamEnded[fastID] && streamEnded[slowID]) {
			f, err := framer.ReadFrame()
			if err != nil {
				log.Fatalf("read frame on trial %d (fast_ended=%v slow_ended=%v): %v",
					i, streamEnded[fastID], streamEnded[slowID], err)
			}
			var sid uint32
			var ended bool
			var isHeaders bool
			switch ft := f.(type) {
			case *http2.HeadersFrame:
				sid, ended, isHeaders = ft.StreamID, ft.StreamEnded(), true
			case *http2.DataFrame:
				sid, ended = ft.StreamID, ft.StreamEnded()
			case *http2.SettingsFrame, *http2.WindowUpdateFrame, *http2.PingFrame:
				continue
			case *http2.GoAwayFrame:
				log.Fatalf("server sent GOAWAY: %v (debug: %q)", ft, string(ft.DebugData()))
			default:
				continue
			}
			// Only care about our two streams.
			if sid != fastID && sid != slowID {
				continue
			}
			// Record the first HEADERS frame we see across both streams —
			// that's our "which response arrived first" signal.
			if isHeaders && !headersSeen[sid] {
				headersSeen[sid] = true
				if res.firstStreamID == 0 {
					res.firstStreamID = sid
				}
			}
			if ended {
				streamEnded[sid] = true
			}
		}

		if i >= *warmup {
			results = append(results, res)
			if *verbose {
				winner := "slow"
				if res.fastWon() {
					winner = "fast"
				}
				fmt.Printf("trial %d: first=%d fast=%d slow=%d winner=%s\n",
					i-*warmup, res.firstStreamID, res.fastStreamID, res.slowStreamID, winner)
			}
			if *progress > 0 && (i-*warmup+1)%*progress == 0 {
				done := i - *warmup + 1
				fmt.Fprintf(os.Stderr, "... %d/%d trials complete\n", done, *trials)
			}
		}
	}

	analyze(results)
}

// dialH2 opens a TLS connection, completes the H2 preface + initial SETTINGS
// exchange, and returns the net.Conn, a buffered writer wrapping the conn,
// and a Framer whose writes go through that buffer. Buffering lets us write
// two HEADERS frames and flush them to the kernel in a single syscall, which
// almost always results in a single TCP segment on loopback/LAN.
func dialH2(addr string) (net.Conn, *bufio.Writer, *http2.Framer, error) {
	raw, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // self-signed lab cert
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if raw.ConnectionState().NegotiatedProtocol != "h2" {
		raw.Close()
		return nil, nil, nil, fmt.Errorf("server did not negotiate h2")
	}
	// Client preface.
	if _, err := raw.Write([]byte(http2.ClientPreface)); err != nil {
		raw.Close()
		return nil, nil, nil, err
	}
	bw := bufio.NewWriter(raw)
	framer := http2.NewFramer(bw, raw)
	// Handshake deadline — if the peer isn't speaking H2, we want an error,
	// not a hang.
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := framer.WriteSettings(); err != nil {
		raw.Close()
		return nil, nil, nil, err
	}
	if err := bw.Flush(); err != nil {
		raw.Close()
		return nil, nil, nil, err
	}
	// Read frames until we've (a) seen the server's SETTINGS and acked it,
	// and (b) seen the server's ack of our SETTINGS. Order isn't guaranteed.
	sawServerSettings := false
	sawOurAck := false
	for !(sawServerSettings && sawOurAck) {
		f, err := framer.ReadFrame()
		if err != nil {
			raw.Close()
			return nil, nil, nil, err
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok {
			continue
		}
		if sf.IsAck() {
			sawOurAck = true
			continue
		}
		if err := framer.WriteSettingsAck(); err != nil {
			raw.Close()
			return nil, nil, nil, err
		}
		if err := bw.Flush(); err != nil {
			raw.Close()
			return nil, nil, nil, err
		}
		sawServerSettings = true
	}
	// Clear the handshake deadline; the caller manages timeouts per trial.
	raw.SetDeadline(time.Time{})
	return raw, bw, framer, nil
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

func analyze(results []trialResult) {
	n := len(results)
	if n == 0 {
		fmt.Println("no trials recorded")
		return
	}
	fastWins := 0
	// Track wins conditioned on the position of /fast in the coalesced pair,
	// so we can see any residual bias from request order.
	fastFirstPosWins, fastFirstPosN := 0, 0
	fastSecondPosWins, fastSecondPosN := 0, 0
	for _, r := range results {
		if r.fastWon() {
			fastWins++
		}
		if r.fastStreamID < r.slowStreamID {
			fastFirstPosN++
			if r.fastWon() {
				fastFirstPosWins++
			}
		} else {
			fastSecondPosN++
			if r.fastWon() {
				fastSecondPosWins++
			}
		}
	}

	p := float64(fastWins) / float64(n)
	// One-sided binomial test vs H0: p = 0.5, H1: p > 0.5.
	pval := oneSidedBinomialPValue(fastWins, n, 0.5)

	fmt.Println("---")
	fmt.Printf("trials:              %d\n", n)
	fmt.Printf("fast arrived first:  %d (%.2f%%)\n", fastWins, 100*p)
	if fastFirstPosN > 0 {
		fmt.Printf("  when fast sent 1st: %d/%d (%.2f%%)\n",
			fastFirstPosWins, fastFirstPosN, 100*float64(fastFirstPosWins)/float64(fastFirstPosN))
	}
	if fastSecondPosN > 0 {
		fmt.Printf("  when fast sent 2nd: %d/%d (%.2f%%)\n",
			fastSecondPosWins, fastSecondPosN, 100*float64(fastSecondPosWins)/float64(fastSecondPosN))
	}
	fmt.Printf("one-sided p-value:   %.3g  (H0: no timing difference)\n", pval)
	// Wilson 95% CI for a proportion — more honest than normal approx at
	// extreme p.
	lo, hi := wilsonCI(fastWins, n, 1.96)
	fmt.Printf("Wilson 95%% CI:       [%.3f, %.3f]\n", lo, hi)

	// If the two position-conditional rates diverge sharply, the signal is
	// contaminated by request-order bias, and -interleave isn't enough.
	// Flag that.
	if fastFirstPosN > 30 && fastSecondPosN > 30 {
		d := math.Abs(float64(fastFirstPosWins)/float64(fastFirstPosN) -
			float64(fastSecondPosWins)/float64(fastSecondPosN))
		if d > 0.15 {
			fmt.Printf("WARNING: position-conditional rates differ by %.2f — "+
				"ordering bias likely dominates. Interpret with caution.\n", d)
		}
	}
}

// oneSidedBinomialPValue returns P(X >= k) under X ~ Binomial(n, p).
// Uses log-space summation to avoid overflow for large n.
func oneSidedBinomialPValue(k, n int, p float64) float64 {
	if k <= 0 {
		return 1.0
	}
	if k > n {
		return 0.0
	}
	logP := math.Log(p)
	logQ := math.Log(1 - p)
	// logC[i] = log C(n, i)
	sum := math.Inf(-1)
	logBinom := 0.0 // log C(n, 0) = 0
	for i := 0; i <= n; i++ {
		if i > 0 {
			// C(n,i) = C(n,i-1) * (n-i+1)/i
			logBinom += math.Log(float64(n-i+1)) - math.Log(float64(i))
		}
		if i >= k {
			term := logBinom + float64(i)*logP + float64(n-i)*logQ
			sum = logSumExp(sum, term)
		}
	}
	return math.Exp(sum)
}

func logSumExp(a, b float64) float64 {
	if math.IsInf(a, -1) {
		return b
	}
	if math.IsInf(b, -1) {
		return a
	}
	if a > b {
		return a + math.Log1p(math.Exp(b-a))
	}
	return b + math.Log1p(math.Exp(a-b))
}

// wilsonCI returns the Wilson score interval for k successes in n trials.
func wilsonCI(k, n int, z float64) (float64, float64) {
	if n == 0 {
		return 0, 1
	}
	p := float64(k) / float64(n)
	N := float64(n)
	denom := 1 + z*z/N
	center := (p + z*z/(2*N)) / denom
	halfWidth := z * math.Sqrt(p*(1-p)/N+z*z/(4*N*N)) / denom
	lo := center - halfWidth
	hi := center + halfWidth
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// sort helper kept so the imports stay honest if you extend the analysis
// with per-trial latency sorting later.
var _ = sort.Ints

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

// silence unused-import complaints from context if you extend with timeouts
var _ = context.Background
