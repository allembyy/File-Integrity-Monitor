package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage:")
		fmt.Println(`  go run . init "<folder-path>"`)
		fmt.Println(`  go run . scan "<folder-path>"`)
		fmt.Println(`  go run . monitor "<folder-path>"`)
		return
	}

	command := os.Args[1]

	if command != "init" && command != "scan" && command != "monitor" {
		fmt.Println("Unknown command:", command)
		fmt.Println(`Use "init", "scan" or "monitor".`)
		return
	}

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

	// Each folder has its own baseline.
	baselinePath, err := baselinePathForFolder(folder)
	if err != nil {
		fmt.Println("Error resolving baseline path:", err)
		return
	}

	// Keep the audit log in the project directory.
	logPath, err := filepath.Abs("audit.log")
	if err != nil {
		fmt.Println("Error resolving audit log path:", err)
		return
	}

	// The audit log must be outside the monitored folder.
	rel, err := filepath.Rel(folder, logPath)
	if err != nil {
		fmt.Println("Error checking audit log path:", err)
		return
	}

	if rel == "." ||
		(rel != ".." &&
			!filepath.IsAbs(rel) &&
			!strings.HasPrefix(
				rel,
				".."+string(os.PathSeparator),
			)) {
		fmt.Println("Error: audit.log must be outside the monitored folder")
		return
	}

	switch command {
	case "init":
		if err := initBaseline(folder, baselinePath); err != nil {
			fmt.Println("Error:", err)
		}

	case "scan", "monitor":
		if err := chooseBaseline(folder, baselinePath); err != nil {
			fmt.Println("Error:", err)
			return
		}

		if command == "scan" {
			if err := scanFolder(folder, baselinePath, logPath); err != nil {
				fmt.Println("Error:", err)
			}
		} else {
			if err := monitorFolder(folder, baselinePath, logPath); err != nil {
				fmt.Println("Error:", err)
			}
		}
	}
}

// chooseBaseline asks the user whether to keep or rebuild the baseline.
func chooseBaseline(folder, baselinePath string) error {
	reader := bufio.NewReader(os.Stdin)

	_, err := os.Stat(baselinePath)

	if err == nil {
		fmt.Println("\nExisting baseline found for this folder.")
		fmt.Println("1. Keep existing baseline")
		fmt.Println("2. Create a new baseline")
		fmt.Print("Choose an option (1/2): ")

		for {
			choice, readErr := reader.ReadString('\n')
			if readErr != nil {
				return fmt.Errorf("could not read choice: %w", readErr)
			}

			choice = strings.TrimSpace(choice)

			if choice == "1" {
				fmt.Println("Keeping the existing baseline.")
				return nil
			}

			if choice == "2" {
				fmt.Print("This replaces the trusted baseline. Continue? (y/n): ")

				confirm, readErr := reader.ReadString('\n')
				if readErr != nil {
					return fmt.Errorf("could not read confirmation: %w", readErr)
				}

				confirm = strings.ToLower(strings.TrimSpace(confirm))

				if confirm != "y" && confirm != "yes" {
					fmt.Println("Baseline unchanged.")
					return fmt.Errorf("baseline rebuild cancelled")
				}

				return initBaseline(folder, baselinePath)
			}

			fmt.Print("Invalid choice. Enter 1 or 2: ")
		}
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("cannot check baseline: %w", err)
	}

	fmt.Println("\nNo baseline exists for this folder.")
	fmt.Print("Create an initial baseline? (y/n): ")

	confirm, readErr := reader.ReadString('\n')
	if readErr != nil {
		return fmt.Errorf("could not read confirmation: %w", readErr)
	}

	confirm = strings.ToLower(strings.TrimSpace(confirm))

	if confirm != "y" && confirm != "yes" {
		return fmt.Errorf("a baseline is required; operation cancelled")
	}

	return initBaseline(folder, baselinePath)
}
