package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func TestNewrelicNrqlGapFillingRule(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "rule_enabled_with_intermittent_data_missing_fill_option",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition" {
  policy_id = "12345"
  name      = "Test Condition"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'MyService'"
  }

  critical {
    operator            = "above"
    threshold           = 10
    threshold_duration  = 300
    threshold_occurrences = "ALL"
  }
}
`,
			Expected: helper.Issues{
				{
					Rule:    NewNewrelicNrqlGapFillingRule(),
					Message: "`fill_option` must be set when using intermittent data sources like 'TransactionError' in `newrelic_nrql_alert_condition`.",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 9, Column: 13},
						End:      hcl.Pos{Line: 9, Column: 80},
					},
				},
			},
		},
		{
			Name: "rule_enabled_with_intermittent_data_fill_option_none",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition_none" {
  policy_id = "12345"
  name      = "Test Condition None"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'MyService'"
  }

  fill_option = "none"

  critical {
    operator            = "above"
    threshold           = 10
    threshold_duration  = 300
    threshold_occurrences = "ALL"
  }
}
`,
			Expected: helper.Issues{
				{
					Rule:    NewNewrelicNrqlGapFillingRule(),
					Message: "`fill_option` should not be 'none' when using intermittent data sources like 'TransactionError' in `newrelic_nrql_alert_condition`. Consider 'last_value' or 'static'.",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 12, Column: 17},
						End:      hcl.Pos{Line: 12, Column: 23},
					},
				},
			},
		},
		{
			Name: "rule_enabled_with_intermittent_data_fill_option_static_missing_fill_value",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition_static_missing_value" {
  policy_id = "12345"
  name      = "Test Condition Static Missing Value"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'MyService'"
  }

  fill_option = "static"

  critical {
    operator            = "above"
    threshold           = 10
    threshold_duration  = 300
    threshold_occurrences = "ALL"
  }
}
`,
			Expected: helper.Issues{
				{
					Rule:    NewNewrelicNrqlGapFillingRule(),
					Message: "`fill_value` must be set when `fill_option` is 'static' for `newrelic_nrql_alert_condition`.",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 12, Column: 17},
						End:      hcl.Pos{Line: 12, Column: 25},
					},
				},
			},
		},
		{
			Name: "rule_enabled_with_intermittent_data_valid_config",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition_valid" {
  policy_id = "12345"
  name      = "Test Condition Valid"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'MyService'"
  }

  fill_option = "last_value"

  critical {
    operator            = "above"
    threshold           = 10
    threshold_duration  = 300
    threshold_occurrences = "ALL"
  }
}

resource "newrelic_nrql_alert_condition" "test_condition_valid_static" {
  policy_id = "12345"
  name      = "Test Condition Valid Static"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'MyService'"
  }

  fill_option = "static"
  fill_value  = 0.0

  critical {
    operator            = "above"
    threshold           = 10
    threshold_duration  = 300
    threshold_occurrences = "ALL"
  }
}
`,
			Expected: helper.Issues{},
		},
		{
			Name: "rule_enabled_non_intermittent_data",
			Content: `
resource "newrelic_nrql_alert_condition" "non_intermittent" {
  policy_id = "67890"
  name      = "Non Intermittent Data"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT average(duration) FROM Transaction WHERE appName = 'MyWebStore'"
  }

  critical {
    operator            = "above"
    threshold           = 0.5
    threshold_duration  = 60
    threshold_occurrences = "ALL"
  }
}
`,
			Expected: helper.Issues{},
		},
		{
			Name: "rule_enabled_nrql_query_missing",
			Content: `
resource "newrelic_nrql_alert_condition" "missing_query" {
  policy_id = "67890"
  name      = "Missing Query Attribute"
  type      = "static"
  enabled   = true

  nrql {
    // query attribute is intentionally missing
  }

  critical {
    operator            = "above"
    threshold           = 0.5
    threshold_duration  = 60
    threshold_occurrences = "ALL"
  }
}
`,
			Expected: helper.Issues{
				{
					Rule:    NewNewrelicNrqlGapFillingRule(),
					Message: "`nrql.query` is missing in `newrelic_nrql_alert_condition`.",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 57},
					},
				},
			},
		},
	}

	rule := NewNewrelicNrqlGapFillingRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})
			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}
			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
