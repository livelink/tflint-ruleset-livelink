package rules

import (
	"fmt"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func TestNewrelicNrqlGapFillingRule(t *testing.T) {
	// Assuming intermittentSources is available and not empty
	firstIntermittent := "TransactionError"
	if len(intermittentSources) > 0 {
		firstIntermittent = intermittentSources[0]
	}

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
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
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
					Rule:    InitNewrelicNrqlGapFillingRule(),
					Message: fmt.Sprintf("`fill_option` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", firstIntermittent),
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 9, Column: 13},
						End:      hcl.Pos{Line: 9, Column: 78},
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
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
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
					Rule:    InitNewrelicNrqlGapFillingRule(),
					Message: fmt.Sprintf("`fill_option` should not be 'none' when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`. Consider 'last_value' or 'static'.", firstIntermittent),
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
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
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
					Rule:    InitNewrelicNrqlGapFillingRule(),
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
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
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
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
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
	}

	rule := InitNewrelicNrqlGapFillingRule()

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

func TestNewrelicSignalLossRule(t *testing.T) {
	// This function helps to find the nrql.query attribute range in the HCL content.
	// The rule appears to be reporting issues on this attribute.
	getNrqlQueryRange := func(t *testing.T, content, resourceName string) hcl.Range {
		parser := hclparse.NewParser()
		f, diags := parser.ParseHCL([]byte(content), "resource.tf")
		if diags.HasErrors() {
			t.Logf("HCL parsing diagnostics: %s", diags)
		}
		if f == nil || f.Body == nil {
			t.Fatalf("Parsing HCL returned a nil file or body")
		}

		bodyContent, contentDiags := f.Body.Content(&hcl.BodySchema{
			Blocks: []hcl.BlockHeaderSchema{
				{Type: "resource", LabelNames: []string{"type", "name"}},
			},
		})
		if contentDiags.HasErrors() {
			t.Fatalf("Failed to get body content: %s", contentDiags)
		}

		for _, resourceBlock := range bodyContent.Blocks {
			if resourceBlock.Type == "resource" && len(resourceBlock.Labels) == 2 && resourceBlock.Labels[0] == "newrelic_nrql_alert_condition" && resourceBlock.Labels[1] == resourceName {
				// Now iterate through the inner blocks of the found resource
				resourceContent, _ := resourceBlock.Body.Content(&hcl.BodySchema{
					Blocks: []hcl.BlockHeaderSchema{{Type: "nrql"}},
				})
				for _, innerBlock := range resourceContent.Blocks {
					if innerBlock.Type == "nrql" {
						// Correctly get the content of the inner block to access its attributes
						nrqlContent, _, _ := innerBlock.Body.PartialContent(&hcl.BodySchema{
							Attributes: []hcl.AttributeSchema{{Name: "query"}},
						})
						if queryAttr, exists := nrqlContent.Attributes["query"]; exists {
							// Return the range of the expression (the value), not the whole attribute.
							return queryAttr.Expr.Range()
						}
					}
				}
				// Fallback to the resource definition range if nrql.query is not found
				return resourceBlock.DefRange
			}
		}
		t.Fatalf("Resource block '%s' not found", resourceName)
		return hcl.Range{}
	}

	firstIntermittent := "TransactionError"
	if len(intermittentSources) > 0 {
		firstIntermittent = intermittentSources[0]
	}

	tests := []struct {
		Name         string
		Content      string
		ResourceName string
		Expected     helper.Issues
	}{
		{
			Name:         "rule_enabled_with_intermittent_data_missing_ignore_on_expected_termination",
			ResourceName: "test_condition_missing_ignore",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition_missing_ignore" {
  policy_id = "12345"
  name      = "Test Condition Missing Ignore"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
  }

  close_violations_on_expiration = true

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
					Rule:    InitNewrelicSignalLossRule(),
					Message: fmt.Sprintf("`ignore_on_expected_termination` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", firstIntermittent),
				},
			},
		},
		{
			Name:         "rule_enabled_with_intermittent_data_missing_close_violations_on_expiration",
			ResourceName: "test_condition_missing_close",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition_missing_close" {
  policy_id = "12345"
  name      = "Test Condition Missing Close"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
  }

  ignore_on_expected_termination = true

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
					Rule:    InitNewrelicSignalLossRule(),
					Message: fmt.Sprintf("`close_violations_on_expiration` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", firstIntermittent),
				},
			},
		},
		{
			Name:         "rule_enabled_with_intermittent_data_valid_config",
			ResourceName: "test_condition_valid_signal_loss",
			Content: `
resource "newrelic_nrql_alert_condition" "test_condition_valid_signal_loss" {
  policy_id = "12345"
  name      = "Test Condition Valid Signal Loss"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT count(*) FROM TransactionError WHERE appName = 'Bauhaus'"
  }

  ignore_on_expected_termination = true
  close_violations_on_expiration = true

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
			Name:         "rule_enabled_non_intermittent_data_signal_loss",
			ResourceName: "non_intermittent_signal_loss",
			Content: `
resource "newrelic_nrql_alert_condition" "non_intermittent_signal_loss" {
  policy_id = "67890"
  name      = "Non Intermittent Data Signal Loss"
  type      = "static"
  enabled   = true

  nrql {
    query = "SELECT average(duration) FROM Transaction WHERE appName = 'Bauhaus'"
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
	}

	rule := InitNewrelicSignalLossRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			// If there are expected issues, set their range dynamically
			if len(test.Expected) > 0 {
				resourceRange := getNrqlQueryRange(t, test.Content, test.ResourceName)
				for i := range test.Expected {
					test.Expected[i].Range = resourceRange
				}
			}

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred during rule check: %s", err)
			}
			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
