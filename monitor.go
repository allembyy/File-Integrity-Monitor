package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ANSI colors for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// printBanner displays the monitoring header.
func printBanner(folder string) {
	fmt.Println()
	fmt.Println(colorCyan + colorBold +
		"╔══════════════════════════════════════════════════════╗")
	fmt.Println(
		"║              FILE INTEGRITY MONITOR                  ║")
	fmt.Println(
		"║                   REAL-TIME MODE                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝" +
		colorReset)

	fmt.Println()
	fmt.Println(colorGreen + "  [✓] Status    : MONITORING" + colorReset)
	fmt.Println(colorWhite + "  [i] Directory : " + folder + colorReset)
	fmt.Println(colorWhite + "  [i] Started   : " +
		time.Now().Format("2006-01-02 15:04:05") + colorReset)
	fmt.Println()
	fmt.Println(colorCyan +
		"──────────────────── EVENT LOG ────────────────────────" +
		colorReset)
	fmt.Println()
}

// printEvent displays a colored file-change event.
func printEvent(event, path string) {
	color := colorWhite
	symbol := "*"

	switch event {
	case "ADDED":
		color = colorGreen
		symbol = "+"
	case "MODIFIED":
		color = colorYellow
		symbol = "~"
	case "DELETED":
		color = colorRed
		symbol = "!"
	case "RENAMED":
		color = colorCyan
		symbol = "»"
	}

	fmt.Printf("%s%s  [%s] %-8s %s%s\n",
		color,
		time.Now().Format("15:04:05"),
		symbol,
		event,
		path,
		colorReset,
	)
}

// addDirectories registers a folder and all its subdirectories.
func addDirectories(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return watcher.Add(path)
		}

		return nil
	})
}

// compareWithBaseline finds files added, modified, or deleted
// since the trusted baseline was created.
func compareWithBaseline(
	folder string,
	known Baseline,
) ([]Change, error) {
	current, err := createBaseline(folder)
	if err != nil {
		return nil, err
	}

	var changes []Change

	for path, currentHash := range current {
		oldHash, exists := known[path]

		if !exists {
			changes = append(changes, Change{
				Event: "ADDED",
				Path:  path,
			})
		} else if oldHash != currentHash {
			changes = append(changes, Change{
				Event: "MODIFIED",
				Path:  path,
			})
		}
	}

	for path := range known {
		if _, exists := current[path]; !exists {
			changes = append(changes, Change{
				Event: "DELETED",
				Path:  path,
			})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path == changes[j].Path {
			return changes[i].Event < changes[j].Event
		}
		return changes[i].Path < changes[j].Path
	})

	return changes, nil
}

// PendingRename tracks a Rename event waiting for a paired Create event.
type PendingRename struct {
	OldPath   string
	Timestamp time.Time
}

// RenamePairer pairs Windows fsnotify Rename and Create events within a time window.
type RenamePairer struct {
	known   Baseline
	window  time.Duration
	clock   Clock
	pending []PendingRename
}

func NewRenamePairer(known Baseline, window time.Duration, clock Clock) *RenamePairer {
	if clock == nil {
		clock = realClock{}
	}
	if window <= 0 {
		window = 500 * time.Millisecond
	}
	return &RenamePairer{
		known:  known,
		window: window,
		clock:  clock,
	}
}

func (p *RenamePairer) HasPending() bool {
	return len(p.pending) > 0
}

func (p *RenamePairer) NextTimeout(now time.Time) time.Duration {
	if len(p.pending) == 0 {
		return 0
	}
	earliest := p.pending[0].Timestamp
	elapsed := now.Sub(earliest)
	if elapsed >= p.window {
		return 0
	}
	return p.window - elapsed
}

func (p *RenamePairer) FlushExpired(now time.Time) []Change {
	cutoff := now.Add(-p.window)
	var active []PendingRename
	var emitted []Change

	for _, item := range p.pending {
		if !item.Timestamp.After(cutoff) {
			if _, exists := p.known[item.OldPath]; exists {
				emitted = append(emitted, Change{
					Event: "DELETED",
					Path:  item.OldPath,
				})
			}
		} else {
			active = append(active, item)
		}
	}

	p.pending = active
	return emitted
}

func (p *RenamePairer) HandleEvent(op fsnotify.Op, path string, now time.Time) []Change {
	emitted := p.FlushExpired(now)

	if op&fsnotify.Rename != 0 {
		p.pending = append(p.pending, PendingRename{
			OldPath:   path,
			Timestamp: now,
		})
		return emitted
	}

	if op&fsnotify.Create != 0 {
		if len(p.pending) > 0 {
			idx := -1
			dir := filepath.Dir(path)
			for i := len(p.pending) - 1; i >= 0; i-- {
				if filepath.Dir(p.pending[i].OldPath) == dir {
					idx = i
					break
				}
			}
			if idx == -1 {
				idx = len(p.pending) - 1
			}

			matched := p.pending[idx]
			p.pending = append(p.pending[:idx], p.pending[idx+1:]...)

			emitted = append(emitted, Change{
				Event:   "RENAMED",
				OldPath: matched.OldPath,
				Path:    path,
			})
			return emitted
		}

		emitted = append(emitted, Change{
			Event: "ADDED",
			Path:  path,
		})
		return emitted
	}

	if op&fsnotify.Remove != 0 {
		if _, exists := p.known[path]; exists {
			emitted = append(emitted, Change{
				Event: "DELETED",
				Path:  path,
			})
		}
		return emitted
	}

	if op&fsnotify.Write != 0 {
		emitted = append(emitted, Change{
			Event: "MODIFIED",
			Path:  path,
		})
		return emitted
	}

	return emitted
}

// monitorFolder checks for changes missed while stopped, then
// watches for new filesystem events in real time.
func monitorFolder(folder, baselinePath, logPath string) error {
	known, err := loadBaseline(baselinePath)
	if err != nil {
		return fmt.Errorf("cannot load baseline: %w", err)
	}

	// Start watching before the initial comparison so changes
	// during the scan can also generate filesystem events.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot create watcher: %w", err)
	}
	defer watcher.Close()

	if err := addDirectories(watcher, folder); err != nil {
		return fmt.Errorf("cannot watch folder: %w", err)
	}

	detector := NewDetector(DetectorConfig{
		Window:         DefaultWindowSeconds * time.Second,
		EventThreshold: DefaultEventThreshold,
		ScoreThreshold: DefaultScoreThreshold,
		Cooldown:       DefaultCooldown,
		LogPath:        logPath,
		Folder:         folder,
	})

	// Compare current files with the original baseline.
	startupChanges, err := compareWithBaseline(folder, known)
	if err != nil {
		return fmt.Errorf("startup integrity scan failed: %w", err)
	}

	printBanner(folder)

	if len(startupChanges) == 0 {
		fmt.Println(colorGreen +
			"  [✓] Startup scan: No changes detected." +
			colorReset)
	} else {
		fmt.Println(colorYellow +
			"  [!] Startup scan: Changes detected since baseline." +
			colorReset)
		fmt.Println()

		if err := appendAuditLog(
			logPath,
			folder,
			startupChanges,
		); err != nil {
			return fmt.Errorf("cannot write startup changes to audit log: %w", err)
		}

		for _, change := range startupChanges {
			relativePath, relErr := filepath.Rel(folder, change.Path)
			if relErr != nil {
				relativePath = change.Path
			}
			printEvent(change.Event, relativePath)
		}

		fmt.Println(colorGreen +
			"          Startup changes written to audit log" +
			colorReset)
	}

	fmt.Println()
	fmt.Println(colorWhite +
		"  Press Ctrl+C to stop monitoring." +
		colorReset)
	fmt.Println()

	// Track events already reported during this monitoring session.
	reported := make(map[string]string)
	pairer := NewRenamePairer(known, 500*time.Millisecond, realClock{})

	var renameTimer *time.Timer
	var renameTimerCh <-chan time.Time

	resetTimer := func() {
		if pairer.HasPending() {
			d := pairer.NextTimeout(time.Now())
			if renameTimer == nil {
				renameTimer = time.NewTimer(d)
			} else {
				if !renameTimer.Stop() {
					select {
					case <-renameTimer.C:
					default:
					}
				}
				renameTimer.Reset(d)
			}
			renameTimerCh = renameTimer.C
		} else {
			if renameTimer != nil {
				renameTimer.Stop()
			}
			renameTimerCh = nil
		}
	}

	handleResolvedChange := func(change Change) {
		switch change.Event {
		case "RENAMED":
			time.Sleep(100 * time.Millisecond)

			oldBaselineHash, tracked := known[change.OldPath]
			var contentStatus string
			if tracked {
				newHash, hashErr := calculateHash(change.Path)
				if hashErr == nil {
					if newHash == oldBaselineHash {
						contentStatus = "content unchanged"
					} else {
						contentStatus = "content modified"
					}
				}
			}

			signature := fmt.Sprintf("RENAMED:%s->%s", change.OldPath, change.Path)
			if reported[change.Path] == signature {
				return
			}
			reported[change.Path] = signature

			if err := appendAuditLog(logPath, folder, []Change{change}); err != nil {
				fmt.Println(colorRed + "Audit log error: " + err.Error() + colorReset)
				return
			}

			oldRel, err := filepath.Rel(folder, change.OldPath)
			if err != nil {
				oldRel = change.OldPath
			}
			newRel, err := filepath.Rel(folder, change.Path)
			if err != nil {
				newRel = change.Path
			}

			printEvent("RENAMED", fmt.Sprintf("%s -> %s", oldRel, newRel))
			if contentStatus != "" {
				statusColor := colorCyan
				if contentStatus == "content modified" {
					statusColor = colorYellow
				}
				fmt.Printf("%s          (%s)%s\n", statusColor, contentStatus, colorReset)
			}
			fmt.Println(colorGreen + "          Audit log updated" + colorReset)
			fmt.Println()

			var entropy float64
			if ent, entErr := ComputeFileEntropy(change.Path, MaxEntropyBytes); entErr == nil {
				entropy = ent
			}
			detector.RecordEventWithTime("RENAMED", change.Path, time.Now(), entropy)

		case "DELETED":
			if _, exists := known[change.Path]; !exists {
				return
			}

			signature := "DELETED"
			if reported[change.Path] == signature {
				return
			}
			reported[change.Path] = signature

			if err := appendAuditLog(logPath, folder, []Change{change}); err != nil {
				fmt.Println(colorRed + "Audit log error: " + err.Error() + colorReset)
				return
			}

			rel, err := filepath.Rel(folder, change.Path)
			if err != nil {
				rel = change.Path
			}

			printEvent("DELETED", rel)
			fmt.Println(colorGreen + "          Audit log updated" + colorReset)
			fmt.Println()

			detector.RecordEventWithTime("DELETED", change.Path, time.Now(), 0)

		case "ADDED":
			time.Sleep(100 * time.Millisecond)
			info, statErr := os.Stat(change.Path)
			if statErr != nil || info.IsDir() {
				return
			}

			hash, hashErr := calculateHash(change.Path)
			if hashErr != nil {
				return
			}

			oldHash, exists := known[change.Path]
			if exists && oldHash == hash {
				delete(reported, change.Path)
				return
			}

			signature := "ADDED:" + hash
			if reported[change.Path] == signature {
				return
			}
			reported[change.Path] = signature

			if err := appendAuditLog(logPath, folder, []Change{change}); err != nil {
				fmt.Println(colorRed + "Audit log error: " + err.Error() + colorReset)
				return
			}

			rel, err := filepath.Rel(folder, change.Path)
			if err != nil {
				rel = change.Path
			}

			printEvent("ADDED", rel)
			fmt.Println(colorGreen + "          Audit log updated" + colorReset)
			fmt.Println()

			var entropy float64
			if ent, entErr := ComputeFileEntropy(change.Path, MaxEntropyBytes); entErr == nil {
				entropy = ent
			}
			detector.RecordEventWithTime("ADDED", change.Path, time.Now(), entropy)

		case "MODIFIED":
			time.Sleep(100 * time.Millisecond)
			info, statErr := os.Stat(change.Path)
			if statErr != nil || info.IsDir() {
				return
			}

			hash, hashErr := calculateHash(change.Path)
			if hashErr != nil {
				return
			}

			oldHash, exists := known[change.Path]
			eventType := "MODIFIED"
			if !exists {
				eventType = "ADDED"
			} else if oldHash == hash {
				delete(reported, change.Path)
				return
			}

			signature := eventType + ":" + hash
			if reported[change.Path] == signature {
				return
			}
			reported[change.Path] = signature

			change.Event = eventType
			if err := appendAuditLog(logPath, folder, []Change{change}); err != nil {
				fmt.Println(colorRed + "Audit log error: " + err.Error() + colorReset)
				return
			}

			rel, err := filepath.Rel(folder, change.Path)
			if err != nil {
				rel = change.Path
			}

			printEvent(eventType, rel)
			fmt.Println(colorGreen + "          Audit log updated" + colorReset)
			fmt.Println()

			var entropy float64
			if ent, entErr := ComputeFileEntropy(change.Path, MaxEntropyBytes); entErr == nil {
				entropy = ent
			}
			detector.RecordEventWithTime(eventType, change.Path, time.Now(), entropy)
		}
	}

	for {
		select {
		case <-renameTimerCh:
			emitted := pairer.FlushExpired(time.Now())
			resetTimer()
			for _, ch := range emitted {
				handleResolvedChange(ch)
			}

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			path, err := filepath.Abs(event.Name)
			if err != nil {
				fmt.Println(colorRed +
					"Cannot resolve event path: " + err.Error() +
					colorReset)
				continue
			}
			path = filepath.Clean(path)

			// Start watching newly created directories.
			if event.Op&fsnotify.Create != 0 {
				info, statErr := os.Stat(path)
				if statErr == nil && info.IsDir() {
					if err := addDirectories(watcher, path); err != nil {
						fmt.Println(colorYellow +
							"Warning: cannot watch new directory: " +
							err.Error() + colorReset)
					}
					continue
				}
			}

			relevant := event.Op & (fsnotify.Create |
				fsnotify.Write |
				fsnotify.Remove |
				fsnotify.Rename)

			if relevant == 0 {
				continue
			}

			emitted := pairer.HandleEvent(event.Op, path, time.Now())
			resetTimer()
			for _, ch := range emitted {
				handleResolvedChange(ch)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Println(colorRed +
				"Watcher error: " + err.Error() +
				colorReset)
		}
	}
}
