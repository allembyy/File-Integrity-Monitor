package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Baseline map[string]string

func calculateHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
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

func scanFolder(folder, baselinePath string) error {
	known, err := loadBaseline(baselinePath)
	if err != nil {
		return fmt.Errorf("cannot load baseline: %w", err)
	}

	current, err := createBaseline(folder)
	if err != nil {
		return err
	}

	modified := 0
	added := 0
	deleted := 0

	fmt.Println("\n--- Integrity Report ---")

	for path, currentHash := range current {
		oldHash, exists := known[path]

		if !exists {
			fmt.Println("[ADDED]    ", path)
			added++
		} else if oldHash != currentHash {
			fmt.Println("[MODIFIED] ", path)
			modified++
		}
	}

	for path := range known {
		if _, exists := current[path]; !exists {
			fmt.Println("[DELETED]  ", path)
			deleted++
		}
	}

	if modified+added+deleted == 0 {
		fmt.Println("No changes detected.")
	}

	fmt.Printf("\nSummary: %d modified, %d added, %d deleted\n",
		modified, added, deleted)

	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage:")
		fmt.Println(`  go run . init "<folder-path>"`)
		fmt.Println(`  go run . scan "<folder-path>"`)
		return
	}

	command := os.Args[1]

	folder, err := filepath.Abs(os.Args[2])
	if err != nil {
		fmt.Println("Error resolving folder:", err)
		return
	}

	info, err := os.Stat(folder)
	if err != nil {
		fmt.Println("Error accessing folder:", err)
		return
	}

	if !info.IsDir() {
		fmt.Println("Error: path is not a folder")
		return
	}

	// Keep the baseline in the project directory.
	baselinePath, err := filepath.Abs("baseline.json")
	if err != nil {
		fmt.Println("Error resolving baseline path:", err)
		return
	}

	// Do not let the baseline file be inside the monitored folder.
	rel, err := filepath.Rel(folder, baselinePath)
	if err != nil {
		fmt.Println("Error checking baseline path:", err)
		return
	}

	if rel == "." || (rel != ".." &&
		!filepath.IsAbs(rel) &&
		!strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		fmt.Println("Error: baseline.json must be outside the monitored folder")
		return
	}

	switch command {
	case "init":
		if err := initBaseline(folder, baselinePath); err != nil {
			fmt.Println("Error:", err)
		}
	case "scan":
		if err := scanFolder(folder, baselinePath); err != nil {
			fmt.Println("Error:", err)
		}
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println(`Use "init" or "scan".`)
	}
}
