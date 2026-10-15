package main

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// fakeClock implements Clock for testing.
type fakeClock struct {
	curr time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.curr
}

func (f *fakeClock) Advance(d time.Duration) {
	f.curr = f.curr.Add(d)
}

func TestComputeEntropy(t *testing.T) {
	// Empty slice
	if e := ComputeEntropy([]byte{}); e != 0.0 {
		t.Fatalf("expected 0.0 for empty slice, got %f", e)
	}

	// Uniform identical bytes
	allZeros := make([]byte, 1024)
	if e := ComputeEntropy(allZeros); e != 0.0 {
		t.Fatalf("expected 0.0 for identical bytes, got %f", e)
	}

	// Normal text should have low to moderate entropy (< 6.0)
	normalText := []byte("The quick brown fox jumps over the lazy dog. 1234567890! Simple text content.")
	eText := ComputeEntropy(normalText)
	if eText > 6.0 || eText < 2.0 {
		t.Fatalf("expected text entropy between 2.0 and 6.0, got %f", eText)
	}

	// Random / encrypted bytes should have high entropy (> 7.5)
	randomBytes := make([]byte, 65536)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}
	eRandom := ComputeEntropy(randomBytes)
	if eRandom <= 7.5 {
		t.Fatalf("expected high entropy > 7.5 for random bytes, got %f", eRandom)
	}
}

func TestDetector_BelowThreshold(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	alertCount := 0

	detector := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 20,
		ScoreThreshold: 20.0,
		Cooldown:       30 * time.Second,
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			alertCount++
		},
	})

	// Feed 10 normal events over 5 seconds (below threshold 20)
	for i := 0; i < 10; i++ {
		triggered := detector.RecordEvent("MODIFIED", fmt.Sprintf("/safe/file_%d.txt", i), 4.0)
		if triggered {
			t.Fatalf("unexpected alert triggered on event %d", i)
		}
		fc.Advance(500 * time.Millisecond)
	}

	if alertCount != 0 {
		t.Fatalf("expected 0 alerts, got %d", alertCount)
	}
}

func TestDetector_AboveThreshold_EventCount(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	alertCount := 0
	var lastAlert AlertInfo

	detector := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 20,
		ScoreThreshold: 100.0, // High score threshold so only event count triggers it
		Cooldown:       30 * time.Second,
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			alertCount++
			lastAlert = info
		},
	})

	// Feed 20 events within 5 seconds (below 10s window)
	for i := 0; i < 20; i++ {
		detector.RecordEvent("MODIFIED", fmt.Sprintf("/work/data_%d.dat", i), 4.5)
		fc.Advance(200 * time.Millisecond)
	}

	if alertCount != 1 {
		t.Fatalf("expected 1 alert triggered by event count, got %d", alertCount)
	}

	if lastAlert.EventCount != 20 {
		t.Fatalf("expected 20 events in alert, got %d", lastAlert.EventCount)
	}

	if len(lastAlert.SamplePaths) > 5 {
		t.Fatalf("expected at most 5 sample paths, got %d", len(lastAlert.SamplePaths))
	}
}

func TestDetector_AboveThreshold_SuspiciousHeuristics(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	alertCount := 0

	detector := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 20,   // Won't reach 20 events
		ScoreThreshold: 20.0, // Will cross score threshold due to heuristics
		Cooldown:       30 * time.Second,
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			alertCount++
		},
	})

	// Feed just 4 events, but with .locked extension and entropy 7.9
	// Each event adds: 1 (base) + 5 (ext) + 5 (entropy) = 11 points
	// 2 events = 22 points >= 20.0 score threshold
	for i := 0; i < 4; i++ {
		detector.RecordEvent("MODIFIED", fmt.Sprintf("/docs/report_%d.docx.locked", i), 7.9)
		fc.Advance(100 * time.Millisecond)
	}

	if alertCount != 1 {
		t.Fatalf("expected 1 alert triggered by suspicious score, got %d", alertCount)
	}
}

func TestDetector_Cooldown(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	alertCount := 0

	detector := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 5,
		ScoreThreshold: 5.0,
		Cooldown:       30 * time.Second,
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			alertCount++
		},
	})

	// 1. Initial burst: 5 events at t=0s -> should trigger alert #1
	for i := 0; i < 5; i++ {
		detector.RecordEvent("MODIFIED", fmt.Sprintf("/folder/file_%d.txt", i), 4.0)
	}
	if alertCount != 1 {
		t.Fatalf("expected 1 alert on initial burst, got %d", alertCount)
	}

	// 2. Advance 10 seconds (inside 30s cooldown window)
	fc.Advance(10 * time.Second)

	// Feed another burst of 5 events -> should be suppressed by cooldown!
	for i := 5; i < 10; i++ {
		detector.RecordEvent("MODIFIED", fmt.Sprintf("/folder/file_%d.txt", i), 4.0)
	}
	if alertCount != 1 {
		t.Fatalf("expected alert to be suppressed during cooldown, got %d alerts", alertCount)
	}

	// 3. Advance past cooldown (e.g. 35 more seconds -> total 45s since last alert)
	fc.Advance(35 * time.Second)

	// Feed another burst -> should trigger alert #2
	for i := 10; i < 15; i++ {
		detector.RecordEvent("MODIFIED", fmt.Sprintf("/folder/file_%d.txt", i), 4.0)
	}
	if alertCount != 2 {
		t.Fatalf("expected second alert after cooldown elapsed, got %d alerts", alertCount)
	}
}

func TestDetector_ReasonText(t *testing.T) {
	// Case 1: event-count rule only
	{
		fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
		var alert AlertInfo
		detector := NewDetector(DetectorConfig{
			Window:         10 * time.Second,
			EventThreshold: 20,
			ScoreThreshold: 200.0, // High score threshold
			Clock:          fc,
			OnAlert: func(info AlertInfo) {
				alert = info
			},
		})

		for i := 0; i < 20; i++ {
			detector.RecordEvent("MODIFIED", fmt.Sprintf("/dir/f_%d.txt", i), 4.0)
		}
		if alert.Reason != "event-count rule" {
			t.Fatalf("expected 'event-count rule', got '%s'", alert.Reason)
		}
	}

	// Case 2: score rule only
	{
		fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
		var alert AlertInfo
		detector := NewDetector(DetectorConfig{
			Window:         10 * time.Second,
			EventThreshold: 20, // High event threshold
			ScoreThreshold: 15.0,
			Clock:          fc,
			OnAlert: func(info AlertInfo) {
				alert = info
			},
		})

		// 3 events with .locked: 3 base + 15 ext = 18 >= 15.0
		for i := 0; i < 3; i++ {
			detector.RecordEvent("MODIFIED", fmt.Sprintf("/dir/f_%d.locked", i), 4.0)
		}
		if alert.Reason != "score rule" {
			t.Fatalf("expected 'score rule', got '%s'", alert.Reason)
		}
	}

	// Case 3: both rules
	{
		fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
		var alert AlertInfo
		detector := NewDetector(DetectorConfig{
			Window:         10 * time.Second,
			EventThreshold: 20,
			ScoreThreshold: 20.0,
			Clock:          fc,
			OnAlert: func(info AlertInfo) {
				alert = info
			},
		})

		// 20 normal events across distinct subdirectories: clustering bonus is 0.
		// At event 19: count=19, score=19 (neither triggers).
		// At event 20: count=20 (>=20) AND score=20.0 (>=20.0) simultaneously trigger.
		for i := 0; i < 20; i++ {
			detector.RecordEvent("MODIFIED", fmt.Sprintf("/dir_%d/f.txt", i), 4.0)
		}
		if alert.Reason != "both" {
			t.Fatalf("expected 'both', got '%s'", alert.Reason)
		}
	}
}

func TestDetector_CompressedExtensionEntropyExclusion(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}

	// 1. High-entropy .docx: should NOT get entropy bonus (+5 each)
	// 4 events on .docx with entropy 7.9:
	// score = 4 (base) + 0 (docx excluded from entropy) = 4.0 < 20.0 -> NO alert
	docxAlertCount := 0
	detectorDocx := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 20,
		ScoreThreshold: 20.0,
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			docxAlertCount++
		},
	})

	for i := 0; i < 4; i++ {
		detectorDocx.RecordEvent("MODIFIED", fmt.Sprintf("/docs/report_%d.docx", i), 7.9)
	}
	if docxAlertCount != 0 {
		t.Fatalf("expected 0 alerts for high-entropy .docx due to compression exclusion, got %d", docxAlertCount)
	}

	// 2. High-entropy .dat: should GET entropy bonus (+5 each)
	// 4 events on .dat with entropy 7.9:
	// score = 4 (base) + 20 (entropy) = 24.0 >= 20.0 -> ALERT
	datAlertCount := 0
	var datAlert AlertInfo
	detectorDat := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 20,
		ScoreThreshold: 20.0,
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			datAlertCount++
			datAlert = info
		},
	})

	for i := 0; i < 4; i++ {
		detectorDat.RecordEvent("MODIFIED", fmt.Sprintf("/data/file_%d.dat", i), 7.9)
	}
	if datAlertCount != 1 {
		t.Fatalf("expected 1 alert for high-entropy .dat, got %d", datAlertCount)
	}
	if datAlert.Reason != "score rule" {
		t.Fatalf("expected 'score rule' for high-entropy .dat alert, got '%s'", datAlert.Reason)
	}
}
