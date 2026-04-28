package firewall

import (
	"github.com/Boxkit-Labs/stellar-address-kit/packages/core-go/address"
	"github.com/Boxkit-Labs/stellar-address-kit/packages/core-go/routing"
)

// Decision represents the action to take for a deposit.
type Decision string

const (
	AutoCredit    Decision = "auto-credit"
	ManualReview  Decision = "manual-review"
	Quarantine    Decision = "quarantine"
)

// FilterDeposit evaluates a RoutingResult and returns a deposit-processing decision.
func FilterDeposit(result routing.RoutingResult) Decision {
	// No warnings + routing source is muxed or memo → AutoCredit
	if len(result.Warnings) == 0 && (result.RoutingSource == "muxed" || result.RoutingSource == "memo") {
		return AutoCredit
	}

	// Track highest severity decision
	highestDecision := AutoCredit

	for _, warning := range result.Warnings {
		var decision Decision

		switch warning.Code {
		case address.WarnContractSenderDetected:
			// Contract sender poses security risk - quarantine immediately
			decision = Quarantine
		case address.WarnMuxedDestinationFromContract:
			// Muxed destination from contract poses security risk - quarantine
			decision = Quarantine
		case address.WarnSmartAccountAmbiguousRouting:
			// Smart account routing ambiguity requires manual review
			decision = ManualReview
		case address.WarnMemoIgnoredForMuxed:
			// Memo ignored could indicate routing ambiguity - requires manual review
			decision = ManualReview
		default:
			// Unknown warnings default to manual review for safety
			decision = ManualReview
		}

		// Multiple warnings → highest severity wins: Quarantine > ManualReview > AutoCredit
		if decision == Quarantine {
			return Quarantine
		} else if decision == ManualReview && highestDecision == AutoCredit {
			highestDecision = ManualReview
		}
	}

	// routing source none → ManualReview
	if result.RoutingSource == "none" && highestDecision == AutoCredit {
		return ManualReview
	}

	return highestDecision
}
