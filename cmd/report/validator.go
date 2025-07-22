package report

import (
	"fmt"

	"github.com/ajkula/cyberraven/cmd/attack"
)

// AttackResultValidator handles validation of attack results data
type AttackResultValidator struct{}

// NewAttackResultValidator creates a new attack result validator
func NewAttackResultValidator() *AttackResultValidator {
	return &AttackResultValidator{}
}

// ValidateAttackResult validates an attack result structure
func (v *AttackResultValidator) ValidateAttackResult(result *attack.AttackResult) error {
	if result == nil {
		return fmt.Errorf("attack result is nil")
	}

	// Basic validation
	if result.SessionID == "" {
		return fmt.Errorf("invalid attack result: missing session ID")
	}

	// Validate target information
	if result.Target.BaseURL == "" {
		return fmt.Errorf("invalid attack result: missing target base URL")
	}

	// Validate timing information
	if result.StartTime.IsZero() {
		return fmt.Errorf("invalid attack result: missing start time")
	}

	if result.EndTime.IsZero() {
		return fmt.Errorf("invalid attack result: missing end time")
	}

	if result.Duration <= 0 {
		return fmt.Errorf("invalid attack result: invalid duration")
	}

	// Validate that at least one module has data (more flexible than checking enabled_modules)
	hasModuleData := false
	if result.APIEnumeration != nil {
		hasModuleData = true
	}
	if result.JWTTesting != nil {
		hasModuleData = true
	}
	if result.InjectionTesting != nil {
		hasModuleData = true
	}
	if result.HMACTesting != nil {
		hasModuleData = true
	}
	if result.DoSTesting != nil {
		hasModuleData = true
	}
	if result.TLSTesting != nil {
		hasModuleData = true
	}

	if !hasModuleData {
		return fmt.Errorf("invalid attack result: no module data found")
	}

	return nil
}

// ValidateAttackResults validates a slice of attack results
func (v *AttackResultValidator) ValidateAttackResults(results []*attack.AttackResult) error {
	if len(results) == 0 {
		return fmt.Errorf("no attack results to validate")
	}

	for i, result := range results {
		if err := v.ValidateAttackResult(result); err != nil {
			return fmt.Errorf("validation failed for result %d: %w", i, err)
		}
	}

	return nil
}
