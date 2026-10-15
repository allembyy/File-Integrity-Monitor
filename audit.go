package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Change struct {
	Event   string
	Path    string
	OldPath string
}

func appendAuditLog(logPath, folder string, changes []Change) error {
	if len(changes) == 0 {
		return nil
	}

	file, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("cannot open audit log: %w", err)
	}
	defer file.Close()

	for _, change := range changes {
		relativePath, err := filepath.Rel(folder, change.Path)
		if err != nil {
			relativePath = change.Path
		}

		if change.OldPath != "" {
			oldRel, err := filepath.Rel(folder, change.OldPath)
			if err != nil {
				oldRel = change.OldPath
			}
			relativePath = fmt.Sprintf("%s -> %s", oldRel, relativePath)
		}

		timestamp := time.Now().Format(time.RFC3339)

		_, err = fmt.Fprintf(
			file,
			"[%s] %-8s %s\n",
			timestamp,
			change.Event,
			relativePath,
		)
		if err != nil {
			return fmt.Errorf("cannot write audit log: %w", err)
		}
	}

	return nil
}
