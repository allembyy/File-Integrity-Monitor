package main

import (
	"fmt"
	"sort"
)

func scanFolder(folder, baselinePath, logPath string) error {
	known, err := loadBaseline(baselinePath)
	if err != nil {
		return fmt.Errorf("cannot load baseline: %w", err)
	}

	current, err := createBaseline(folder)
	if err != nil {
		return err
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

	modified := 0
	added := 0
	deleted := 0

	fmt.Println("\n--- Integrity Report ---")

	for _, change := range changes {
		fmt.Printf("[%s] %s\n", change.Event, change.Path)

		switch change.Event {
		case "MODIFIED":
			modified++
		case "ADDED":
			added++
		case "DELETED":
			deleted++
		}
	}

	if len(changes) == 0 {
		fmt.Println("No changes detected.")
	}

	fmt.Printf(
		"\nSummary: %d modified, %d added, %d deleted\n",
		modified, added, deleted,
	)

	if err := appendAuditLog(logPath, folder, changes); err != nil {
		return err
	}

	if len(changes) > 0 {
		fmt.Println("Audit log updated:", logPath)
	}

	return nil
}
