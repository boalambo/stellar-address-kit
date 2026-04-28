package firewall

import (
	"testing"

	"github.com/Boxkit-Labs/stellar-address-kit/packages/core-go/address"
	"github.com/Boxkit-Labs/stellar-address-kit/packages/core-go/routing"
)

func TestFilterDepositFromResult(t *testing.T) {
	tests := []struct {
		name     string
		result   routing.RoutingResult
		expected Decision
	}{
		{
			name: "AutoCredit with muxed source and no warnings",
			result: routing.RoutingResult{
				RoutingSource: "muxed",
				Warnings:      []address.Warning{},
			},
			expected: AutoCredit,
		},
		{
			name: "AutoCredit with memo source and no warnings",
			result: routing.RoutingResult{
				RoutingSource: "memo",
				Warnings:      []address.Warning{},
			},
			expected: AutoCredit,
		},
		{
			name: "ManualReview with no routing source",
			result: routing.RoutingResult{
				RoutingSource: "none",
				Warnings:      []address.Warning{},
			},
			expected: ManualReview,
		},
		{
			name: "Quarantine for contract sender warning",
			result: routing.RoutingResult{
				RoutingSource: "memo",
				Warnings: []address.Warning{
					{Code: address.WarnContractSenderDetected},
				},
			},
			expected: Quarantine,
		},
		{
			name: "ManualReview for memo ignored warning",
			result: routing.RoutingResult{
				RoutingSource: "muxed",
				Warnings: []address.Warning{
					{Code: address.WarnMemoIgnoredForMuxed},
				},
			},
			expected: ManualReview,
		},
		{
			name: "ManualReview for memo present with muxed warning",
			result: routing.RoutingResult{
				RoutingSource: "muxed",
				Warnings: []address.Warning{
					{Code: address.WarnMemoPresentWithMuxed},
				},
			},
			expected: ManualReview,
		},
		{
			name: "Quarantine for invalid destination warning",
			result: routing.RoutingResult{
				RoutingSource: "none",
				Warnings: []address.Warning{
					{Code: address.WarnInvalidDestination},
				},
			},
			expected: Quarantine,
		},
		{
			name: "ManualReview for smart account ambiguous routing",
			result: routing.RoutingResult{
				RoutingSource: "memo",
				Warnings: []address.Warning{
					{Code: address.WarnSmartAccountAmbiguousRouting},
				},
			},
			expected: ManualReview,
		},
		{
			name: "Quarantine for muxed destination from contract",
			result: routing.RoutingResult{
				RoutingSource: "memo",
				Warnings: []address.Warning{
					{Code: address.WarnMuxedDestinationFromContract},
				},
			},
			expected: Quarantine,
		},
		{
			name: "ManualReview for unknown warning",
			result: routing.RoutingResult{
				RoutingSource: "memo",
				Warnings: []address.Warning{
					{Code: "UNKNOWN_WARNING"},
				},
			},
			expected: ManualReview,
		},
		{
			name: "Quarantine takes priority over ManualReview",
			result: routing.RoutingResult{
				RoutingSource: "muxed",
				Warnings: []address.Warning{
					{Code: address.WarnMemoIgnoredForMuxed},
					{Code: address.WarnContractSenderDetected},
				},
			},
			expected: Quarantine,
		},
		{
			name: "ManualReview for multiple manual review warnings",
			result: routing.RoutingResult{
				RoutingSource: "muxed",
				Warnings: []address.Warning{
					{Code: address.WarnMemoIgnoredForMuxed},
					{Code: address.WarnMemoPresentWithMuxed},
				},
			},
			expected: ManualReview,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDepositFromResult(tt.result)
			if got != tt.expected {
				t.Errorf("filterDepositFromResult() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFilterDeposit(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected Decision
	}{
		{
			name:     "empty address returns ManualReview",
			address:  "",
			expected: ManualReview,
		},
		{
			name:     "invalid address format returns ManualReview",
			address:  "INVALID_ADDRESS_FORMAT",
			expected: ManualReview,
		},
		{
			name:     "valid G address returns ManualReview (no routing source)",
			address:  "GDQIDLYENQVSG3VYRPBV3D5LKYQSQZEVJZWTZXKFSXL4UUG3G2J2MSVQ",
			expected: ManualReview,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterDeposit(tt.address)
			if got != tt.expected {
				t.Errorf("FilterDeposit(%q) = %v, want %v", tt.address, got, tt.expected)
			}
		})
	}
}
