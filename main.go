package main

import (
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

	baselinePath, err := filepath.Abs("baseline.json")
	if err != nil {
		fmt.Println("Error resolving baseline path:", err)
		return
	}

	logPath, err := filepath.Abs("audit.log")
	if err != nil {
		fmt.Println("Error resolving audit log path:", err)
		return
	}

	for _, protectedPath := range []string{
		baselinePath,
		logPath,
	} {
		rel, err := filepath.Rel(folder, protectedPath)
		if err != nil {
			fmt.Println("Error checking protected path:", err)
			return
		}

		if rel == "." ||
			(rel != ".." &&
				!filepath.IsAbs(rel) &&
				!strings.HasPrefix(
					rel,
					".."+string(os.PathSeparator),
				)) {
			fmt.Println(
				"Error: baseline.json and audit.log must be outside the monitored folder",
			)
			return
		}
	}

	switch command {
	case "init":
		if err := initBaseline(folder, baselinePath); err != nil {
			fmt.Println("Error:", err)
		}
	case "scan":
		if err := scanFolder(folder, baselinePath, logPath); err != nil {
			fmt.Println("Error:", err)
		}
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println(`Use "init" or "scan".`)
	}
}
