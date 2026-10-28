# Tests for the target_distribution helper (ADR-0070).
# Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

test_target_distribution_defaults_to_vanilla_without_context if {
	proposal.target_distribution == "vanilla" with input as {"proposal": {"files": []}}
}

test_target_distribution_defaults_to_vanilla_when_target_has_none if {
	proposal.target_distribution == "vanilla" with input as {
		"proposal": {"files": []},
		"context": {"target": {"name": "gke", "tier": "prod", "kind": "kubernetes"}},
	}
}

test_target_distribution_reads_openshift if {
	proposal.target_distribution == "openshift" with input as {
		"proposal": {"files": []},
		"context": {"target": {"name": "ocp", "tier": "prod", "distribution": "openshift"}},
	}
}

test_target_distribution_ignores_an_empty_value if {
	proposal.target_distribution == "vanilla" with input as {
		"proposal": {"files": []},
		"context": {"target": {"distribution": ""}},
	}
}
