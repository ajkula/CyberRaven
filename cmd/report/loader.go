package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ajkula/cyberraven/cmd/attack"
)

// AttackResultsLoader handles loading attack results from files
type AttackResultsLoader struct {
	formatter *ConsoleFormatter
}

// NewAttackResultsLoader creates a new attack results loader
func NewAttackResultsLoader(formatter *ConsoleFormatter) *AttackResultsLoader {
	return &AttackResultsLoader{
		formatter: formatter,
	}
}

// LoadAttackResults loads attack results from file or directory
func (l *AttackResultsLoader) LoadAttackResults(inputPath string) ([]*attack.AttackResult, error) {
	var results []*attack.AttackResult

	// Check if input is file or directory
	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, fmt.Errorf("input path does not exist: %w", err)
	}

	if info.IsDir() {
		// Load all JSON files from directory
		files, err := filepath.Glob(filepath.Join(inputPath, "*.json"))
		if err != nil {
			return nil, fmt.Errorf("failed to list JSON files: %w", err)
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("no JSON files found in directory: %s", inputPath)
		}

		for _, file := range files {
			result, err := l.loadSingleAttackResult(file)
			if err != nil {
				// Skip invalid files but continue processing
				l.formatter.PrintWarning(fmt.Sprintf("Failed to load %s: %v", file, err))
				continue
			}
			results = append(results, result)
		}
	} else {
		// Load single file
		result, err := l.loadSingleAttackResult(inputPath)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid attack results found")
	}

	return results, nil
}

// loadSingleAttackResult loads attack result from a single JSON file
func (l *AttackResultsLoader) loadSingleAttackResult(filePath string) (*attack.AttackResult, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Unmarshal JSON
	var result attack.AttackResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &result, nil
}
