package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type Baseline map[string]string

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

func initBaseline(folder, baselinePath string) error {
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
