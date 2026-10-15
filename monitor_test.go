package main

import (
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestRenamePairer_RenameAndCreate(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	known := Baseline{
		"/test/old.txt": "somehash",
	}

	pairer := NewRenamePairer(known, 500*time.Millisecond, fc)

	// 1. Rename event arrives for old file
	emitted := pairer.HandleEvent(fsnotify.Rename, "/test/old.txt", fc.Now())
	if len(emitted) != 0 {
		t.Fatalf("expected 0 emitted events while holding rename, got %d", len(emitted))
	}
	if !pairer.HasPending() {
		t.Fatalf("expected pairer to have pending rename")
	}

	// 2. Advance clock 100ms (inside 500ms window)
	fc.Advance(100 * time.Millisecond)

	// 3. Create event arrives for new file
	emitted = pairer.HandleEvent(fsnotify.Create, "/test/new.txt", fc.Now())
	if len(emitted) != 1 {
		t.Fatalf("expected 1 paired event, got %d", len(emitted))
	}

	event := emitted[0]
	if event.Event != "RENAMED" {
		t.Fatalf("expected event RENAMED, got %s", event.Event)
	}
	if event.OldPath != "/test/old.txt" {
		t.Fatalf("expected OldPath '/test/old.txt', got '%s'", event.OldPath)
	}
	if event.Path != "/test/new.txt" {
		t.Fatalf("expected Path '/test/new.txt', got '%s'", event.Path)
	}
	if pairer.HasPending() {
		t.Fatalf("expected pending renames to be cleared after pairing")
	}
}

func TestRenamePairer_RenameNoCreate_Tracked(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	known := Baseline{
		"/test/tracked.txt": "somehash",
	}

	pairer := NewRenamePairer(known, 500*time.Millisecond, fc)

	// Rename arrives for tracked file
	emitted := pairer.HandleEvent(fsnotify.Rename, "/test/tracked.txt", fc.Now())
	if len(emitted) != 0 {
		t.Fatalf("expected 0 emitted events while holding rename, got %d", len(emitted))
	}

	// Advance clock beyond 500ms window (e.g. 600ms) with no Create
	fc.Advance(600 * time.Millisecond)
	emitted = pairer.FlushExpired(fc.Now())

	if len(emitted) != 1 {
		t.Fatalf("expected 1 emitted event on expired rename of tracked file, got %d", len(emitted))
	}
	if emitted[0].Event != "DELETED" {
		t.Fatalf("expected DELETED event, got %s", emitted[0].Event)
	}
	if emitted[0].Path != "/test/tracked.txt" {
		t.Fatalf("expected path '/test/tracked.txt', got '%s'", emitted[0].Path)
	}
}

func TestRenamePairer_RenameNoCreate_Untracked(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	known := Baseline{} // Empty baseline; file is untracked

	pairer := NewRenamePairer(known, 500*time.Millisecond, fc)

	// Rename arrives for untracked file
	pairer.HandleEvent(fsnotify.Rename, "/test/untracked.txt", fc.Now())

	// Advance clock beyond 500ms window with no Create
	fc.Advance(600 * time.Millisecond)
	emitted := pairer.FlushExpired(fc.Now())

	if len(emitted) != 0 {
		t.Fatalf("expected 0 emitted events for untracked expired rename, got %d", len(emitted))
	}
}

func TestRenamePairer_CreateAlone(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	known := Baseline{}

	pairer := NewRenamePairer(known, 500*time.Millisecond, fc)

	// Create event with no prior Rename
	emitted := pairer.HandleEvent(fsnotify.Create, "/test/created.txt", fc.Now())

	if len(emitted) != 1 {
		t.Fatalf("expected 1 emitted event for standalone create, got %d", len(emitted))
	}
	if emitted[0].Event != "ADDED" {
		t.Fatalf("expected ADDED event, got %s", emitted[0].Event)
	}
	if emitted[0].Path != "/test/created.txt" {
		t.Fatalf("expected path '/test/created.txt', got '%s'", emitted[0].Path)
	}
}

func TestRenamePairer_RenameToLocked_DetectorScore(t *testing.T) {
	fc := &fakeClock{curr: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	known := Baseline{
		"/work/file.txt": "dummyhash",
	}

	pairer := NewRenamePairer(known, 500*time.Millisecond, fc)

	// 1. Rename and Create pair within window
	pairer.HandleEvent(fsnotify.Rename, "/work/file.txt", fc.Now())
	fc.Advance(50 * time.Millisecond)
	emitted := pairer.HandleEvent(fsnotify.Create, "/work/file.txt.locked", fc.Now())

	if len(emitted) != 1 || emitted[0].Event != "RENAMED" {
		t.Fatalf("expected 1 RENAMED event, got %v", emitted)
	}

	// 2. Feed the paired event to Detector
	var alert AlertInfo
	alertCount := 0
	detector := NewDetector(DetectorConfig{
		Window:         10 * time.Second,
		EventThreshold: 20,
		ScoreThreshold: 6.0, // 1 base + 5 suspicious ext = 6.0 points
		Clock:          fc,
		OnAlert: func(info AlertInfo) {
			alertCount++
			alert = info
		},
	})

	// Record paired event targeting the new path (with extension .locked)
	detector.RecordEventWithTime(emitted[0].Event, emitted[0].Path, fc.Now(), 0.0)

	if alertCount != 1 {
		t.Fatalf("expected 1 alert triggered by suspicious .locked rename, got %d", alertCount)
	}
	if alert.Score < 6.0 {
		t.Fatalf("expected score >= 6.0 (base + suspicious extension), got %f", alert.Score)
	}
	if alert.Reason != "score rule" {
		t.Fatalf("expected reason 'score rule', got '%s'", alert.Reason)
	}
}
