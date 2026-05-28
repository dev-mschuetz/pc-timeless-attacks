package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

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

	// Shared HPACK encoder. /fast and /slow have symmetric header sizes (same method, authority, scheme; paths differ only in last 4 bytes).
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
		// Alternate which path gets the lower stream ID to cancel fixed server ordering bias. 
		// Lower ID is always sent first on the wire (H2 requires strictly-increasing stream IDs).
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

		// Encode both header blocks up front so both WriteHeaders calls are back-to-back with no computation between them.
		firstBlock := encodeHeaders(firstPath)
		secondBlock := encodeHeaders(secondPath)

		// Write both HEADERS frames into the bufio.Writer, then one Flush.
		// The Flush issues a single Write() to the kernel, which on loopback/LAN lands in a single TCP segment.
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

		// Per-trial deadline. 
		// If something goes wrong on one trial we want to abort that trial.
		conn.SetReadDeadline(time.Now().Add(*timeout))

		// Read frames until both streams end. HEADERS and DATA can interleave, so track both streams in parallel.
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
			// Record the first HEADERS frame we see across both streams, that's our "which response arrived first" signal.
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

// dialH2 opens a TLS/H2 connection, completes the SETTINGS handshake, and returns a buffered framer so two HEADERS frames flush in one syscall.
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
	// Handshake deadline, bail fast if the peer isn't speaking H2.
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := framer.WriteSettings(); err != nil {
		raw.Close()
		return nil, nil, nil, err
	}
	if err := bw.Flush(); err != nil {
		raw.Close()
		return nil, nil, nil, err
	}
	// Wait for the server's SETTINGS and its ack of ours (order not guaranteed).
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
	// Track wins by /fast's position to detect residual ordering bias.
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
	// Wilson 95% CI — more accurate than normal approximation near p=0/1.
	lo, hi := wilsonCI(fastWins, n, 1.96)
	fmt.Printf("Wilson 95%% CI:       [%.3f, %.3f]\n", lo, hi)

	// Warn if ordering bias is dominating the signal despite -interleave.
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
