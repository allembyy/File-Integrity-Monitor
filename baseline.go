package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Baseline map[string]string

// baselinePathForFolder returns a unique baseline path for each folder.
func baselinePathForFolder(folder string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate user config directory: %w", err)
	}

	normalized := strings.ToLower(filepath.Clean(folder))
	key := sha256.Sum256([]byte(normalized))
	filename := hex.EncodeToString(key[:]) + ".json"

	return filepath.Join(
		configDir,
		"FileIntegrityMonitor",
		"baselines",
		filename,
	), nil
}

func createBaseline(folder string) (Baseline, error) {
	baseline := make(Baseline)

	err := filepath.WalkDir(folder, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return nil
		}

		hash, err := calculateHash(path)
		if err != nil {
			return fmt.Errorf("cannot hash %s: %w", path, err)
		}

		baseline[path] = hash
		fmt.Println("Hashed:", path)

		return nil
	})

	return baseline, err
}

func saveBaseline(path string, baseline Baseline) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create baseline directory: %w", err)
	}

	data, err := json.MarshalIndent(baseline, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func loadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}

	if baseline == nil {
		return nil, fmt.Errorf("baseline is empty or invalid")
	}

	return baseline, nil
}

// ensureBaseline loads an existing baseline or asks before creating one.
func ensureBaseline(folder, baselinePath string) error {
	_, err := os.Stat(baselinePath)

	if err == nil {
		fmt.Println("Existing baseline found. Keeping it.")
		fmt.Println("Baseline:", baselinePath)
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("cannot check baseline: %w", err)
	}

	fmt.Println("No baseline exists for this folder.")
	fmt.Print("Create a baseline from its current contents? (y/n): ")

	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return fmt.Errorf("could not read your choice: %w", err)
	}

	if !strings.EqualFold(strings.TrimSpace(answer), "y") &&
		!strings.EqualFold(strings.TrimSpace(answer), "yes") {
		return fmt.Errorf("baseline creation cancelled")
	}

	current, err := createBaseline(folder)
	if err != nil {
		return err
	}

	if err := saveBaseline(baselinePath, current); err != nil {
		return err
	}

	fmt.Println("\nBaseline created successfully!")
	fmt.Println("Files recorded:", len(current))
	fmt.Println("Saved to:", baselinePath)

	return nil
}

// initBaseline explicitly creates or rebuilds a baseline.
// Existing baselines require confirmation before replacement.
func initBaseline(folder, baselinePath string) error {
	if _, err := os.Stat(baselinePath); err == nil {
		fmt.Println("A baseline already exists for this folder.")
		fmt.Print("Rebuild it using the current contents? (y/n): ")

		var answer string
		if _, err := fmt.Scanln(&answer); err != nil {
			return fmt.Errorf("could not read your choice: %w", err)
		}

		if !strings.EqualFold(strings.TrimSpace(answer), "y") &&
			!strings.EqualFold(strings.TrimSpace(answer), "yes") {
			return fmt.Errorf("baseline rebuild cancelled")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot check baseline: %w", err)
	}

	current, err := createBaseline(folder)
	if err != nil {
		return err
	}

	if err := saveBaseline(baselinePath, current); err != nil {
		return err
	}

	fmt.Println("\nBaseline created successfully!")
	fmt.Println("Files recorded:", len(current))
	fmt.Println("Saved to:", baselinePath)

	return nil
}
