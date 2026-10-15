package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Default configuration parameters for ransomware detection.
const (
	DefaultWindowSeconds  = 10
	DefaultEventThreshold = 20
	DefaultScoreThreshold = 20.0
	DefaultCooldown       = 30 * time.Second
	EntropyThreshold      = 7.5
	MaxEntropyBytes       = 1024 * 1024 // 1 MB
)

// SuspiciousExtensions contains extensions commonly appended by ransomware.
var SuspiciousExtensions = map[string]bool{
	".locked":    true,
	".encrypted": true,
	".crypt":     true,
	".crypto":    true,
	".enc":       true,
	".ransom":    true,
	".wnry":      true,
	".clop":      true,
	".locky":     true,
	".cerber":    true,
	".ryuk":      true,
}

// CompressedOrHighEntropyExtensions contains extensions of files that are normally
// compressed or high entropy by nature, so they are excluded from the entropy bonus.
var CompressedOrHighEntropyExtensions = map[string]bool{
	".zip":  true,
	".7z":   true,
	".rar":  true,
	".gz":   true,
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".webp": true,
	".mp3":  true,
	".mp4":  true,
	".mkv":  true,
	".pdf":  true,
	".docx": true,
	".xlsx": true,
	".pptx": true,
}

// Clock abstracts time for deterministic testing.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

// ChangeEvent represents a filesystem event evaluated by the detector.
type ChangeEvent struct {
	Event     string    // "ADDED", "MODIFIED", "DELETED", "RENAMED"
	Path      string    // Absolute or relative path
	Timestamp time.Time // When the event occurred
	Entropy   float64   // Shannon entropy (0.0 to 8.0)
}

// AlertInfo summarizes the detected ransomware-like pattern.
type AlertInfo struct {
	Timestamp   time.Time
	Reason      string // "event-count rule", "score rule", or "both"
	EventCount  int
	Window      time.Duration
	Score       float64
	SamplePaths []string
}

// DetectorConfig holds tunable parameters for the detector.
type DetectorConfig struct {
	Window         time.Duration
	EventThreshold int
	ScoreThreshold float64
	Cooldown       time.Duration
	Clock          Clock
	LogPath        string
	Folder         string
	OnAlert        func(AlertInfo)
}

// Detector monitors incoming change events for ransomware patterns.
type Detector struct {
	mu             sync.Mutex
	clock          Clock
	window         time.Duration
	eventThreshold int
	scoreThreshold float64
	cooldown       time.Duration
	lastAlertTime  time.Time
	events         []ChangeEvent
	logPath        string
	folder         string
	onAlert        func(AlertInfo)
}

// NewDetector creates a new Detector with the specified or default configuration.
func NewDetector(cfg DetectorConfig) *Detector {
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindowSeconds * time.Second
	}
	if cfg.EventThreshold <= 0 {
		cfg.EventThreshold = DefaultEventThreshold
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = DefaultScoreThreshold
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultCooldown
	}

	return &Detector{
		clock:          cfg.Clock,
		window:         cfg.Window,
		eventThreshold: cfg.EventThreshold,
		scoreThreshold: cfg.ScoreThreshold,
		cooldown:       cfg.Cooldown,
		logPath:        cfg.LogPath,
		folder:         cfg.Folder,
		onAlert:        cfg.OnAlert,
	}
}

// ComputeEntropy calculates Shannon entropy for the given byte slice.
// Returns a value between 0.0 (no variance / all same byte) and 8.0 (uniform randomness).
func ComputeEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	total := float64(len(data))
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ComputeFileEntropy reads up to maxBytes from the file and computes Shannon entropy.
func ComputeFileEntropy(filePath string, maxBytes int64) (float64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if maxBytes <= 0 {
		maxBytes = MaxEntropyBytes
	}

	buffer := make([]byte, maxBytes)
	n, err := io.ReadFull(file, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, err
	}

	return ComputeEntropy(buffer[:n]), nil
}

// IsSuspiciousExtension checks if a path ends with a known ransomware extension.
func IsSuspiciousExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return SuspiciousExtensions[ext]
}

// IsCompressedOrHighEntropyExtension checks if a path ends with an extension that is normally compressed.
func IsCompressedOrHighEntropyExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return CompressedOrHighEntropyExtensions[ext]
}

// RecordEvent processes a single change event with current clock time.
func (d *Detector) RecordEvent(event, path string, entropy float64) bool {
	return d.RecordEventWithTime(event, path, d.clock.Now(), entropy)
}

// RecordEventWithTime processes a change event with an explicit timestamp.
func (d *Detector) RecordEventWithTime(event, path string, timestamp time.Time, entropy float64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if timestamp.IsZero() {
		timestamp = d.clock.Now()
	}
	now := timestamp

	ce := ChangeEvent{
		Event:     event,
		Path:      path,
		Timestamp: now,
		Entropy:   entropy,
	}

	// 1. Sliding window: prune events older than (now - window)
	cutoff := now.Add(-d.window)
	filtered := make([]ChangeEvent, 0, len(d.events)+1)
	for _, e := range d.events {
		if !e.Timestamp.Before(cutoff) {
			filtered = append(filtered, e)
		}
	}
	filtered = append(filtered, ce)
	d.events = filtered

	// 2. Compute suspicion score
	// - Base: 1 point per event in window
	score := float64(len(filtered))

	folderCounts := make(map[string]int)
	suspiciousExtCount := 0
	highEntropyCount := 0

	for _, e := range filtered {
		// Heuristic A: Suspicious file extension (+5 each)
		if IsSuspiciousExtension(e.Path) {
			suspiciousExtCount++
			score += 5.0
		}

		// Heuristic B: High Shannon entropy on modified/added files (+5 each),
		// skipping extensions that are normally compressed or high entropy.
		if e.Entropy >= EntropyThreshold && !IsCompressedOrHighEntropyExtension(e.Path) {
			highEntropyCount++
			score += 5.0
		}

		// Heuristic C: Directory clustering (+3 per folder with >= 5 events)
		dir := filepath.Dir(e.Path)
		folderCounts[dir]++
	}

	for _, count := range folderCounts {
		if count >= 5 {
			score += float64(count) * 0.5
		}
	}

	// 3. Check trigger conditions:
	// - Event count within window >= eventThreshold, OR
	// - Overall suspicion score >= scoreThreshold
	eventCountTriggered := len(filtered) >= d.eventThreshold
	scoreTriggered := score >= d.scoreThreshold

	if !eventCountTriggered && !scoreTriggered {
		return false
	}

	var reason string
	if eventCountTriggered && scoreTriggered {
		reason = "both"
	} else if eventCountTriggered {
		reason = "event-count rule"
	} else {
		reason = "score rule"
	}

	// 4. Cooldown check: avoid alert spam during continuous bursts
	if !d.lastAlertTime.IsZero() && now.Sub(d.lastAlertTime) < d.cooldown {
		return false
	}

	d.lastAlertTime = now

	// 5. Build sample file paths (up to 5 unique paths)
	seenPaths := make(map[string]bool)
	var samplePaths []string
	for i := len(filtered) - 1; i >= 0 && len(samplePaths) < 5; i-- {
		p := filtered[i].Path
		if !seenPaths[p] {
			seenPaths[p] = true
			samplePaths = append(samplePaths, p)
		}
	}

	alert := AlertInfo{
		Timestamp:   now,
		Reason:      reason,
		EventCount:  len(filtered),
		Window:      d.window,
		Score:       score,
		SamplePaths: samplePaths,
	}

	// Display prominent red terminal banner
	d.printAlertBanner(alert)

	// Append RANSOMWARE_SUSPECTED entry to audit.log
	if d.logPath != "" {
		_ = d.appendAlertLog(alert)
	}

	if d.onAlert != nil {
		d.onAlert(alert)
	}

	return true
}

// printAlertBanner outputs a formatted, eye-catching red alert banner in the terminal.
func (d *Detector) printAlertBanner(alert AlertInfo) {
	fmt.Println()
	fmt.Println(colorRed + colorBold +
		"╔══════════════════════════════════════════════════════════════╗")
	fmt.Println(
		"║            [!] CRITICAL SECURITY ALERT: RANSOMWARE           ║")
	fmt.Println(
		"║            SUSPICIOUS BURST / ENCRYPTION ACTIVITY            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝" +
		colorReset)

	fmt.Printf(colorRed+"  [!] Trigger Reason   : %s\n"+colorReset, alert.Reason)

	switch alert.Reason {
	case "event-count rule":
		fmt.Printf(colorRed+"  [!] Events in Window : %d events (Threshold: %d) across %v\n"+colorReset,
			alert.EventCount, d.eventThreshold, alert.Window)
		fmt.Printf(colorRed+"  [!] Suspicion Score  : %.1f\n"+colorReset,
			alert.Score)
	case "score rule":
		fmt.Printf(colorRed+"  [!] Events in Window : %d events across %v\n"+colorReset,
			alert.EventCount, alert.Window)
		fmt.Printf(colorRed+"  [!] Suspicion Score  : %.1f (Threshold: %.1f)\n"+colorReset,
			alert.Score, d.scoreThreshold)
	default: // "both"
		fmt.Printf(colorRed+"  [!] Events in Window : %d events (Threshold: %d) across %v\n"+colorReset,
			alert.EventCount, d.eventThreshold, alert.Window)
		fmt.Printf(colorRed+"  [!] Suspicion Score  : %.1f (Threshold: %.1f)\n"+colorReset,
			alert.Score, d.scoreThreshold)
	}

	fmt.Println(colorYellow + "  [!] Sample Files Affected:" + colorReset)

	for _, sample := range alert.SamplePaths {
		display := sample
		if d.folder != "" {
			if rel, err := filepath.Rel(d.folder, sample); err == nil {
				display = rel
			}
		}
		fmt.Printf(colorYellow+"      • %s\n"+colorReset, display)
	}
	fmt.Println(colorRed + colorBold +
		"──────────────────────────────────────────────────────────────" +
		colorReset)
	fmt.Println()
}

// appendAlertLog logs the ransomware alert directly into audit.log.
func (d *Detector) appendAlertLog(alert AlertInfo) error {
	file, err := os.OpenFile(
		d.logPath,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("cannot open audit log for ransomware alert: %w", err)
	}
	defer file.Close()

	timestamp := alert.Timestamp.Format(time.RFC3339)
	var relSamples []string
	for _, p := range alert.SamplePaths {
		rel := p
		if d.folder != "" {
			if r, err := filepath.Rel(d.folder, p); err == nil {
				rel = r
			}
		}
		relSamples = append(relSamples, rel)
	}

	samplesStr := strings.Join(relSamples, ", ")
	windowSec := int(alert.Window.Seconds())

	_, err = fmt.Fprintf(
		file,
		"[%s] RANSOMWARE_SUSPECTED reason=%s count=%d window=%ds score=%.1f samples=[%s]\n",
		timestamp,
		alert.Reason,
		alert.EventCount,
		windowSec,
		alert.Score,
		samplesStr,
	)
	return err
}
