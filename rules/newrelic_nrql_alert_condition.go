package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// Global list of intermittent data sources
var intermittentSources = []string{
	"TransactionError",
	"transactionName = 'Controller/Rack/get'",
}

func getIntermittentRegex() *regexp.Regexp {
	escaped := make([]string, len(intermittentSources))
	for i, source := range intermittentSources {
		escaped[i] = regexp.QuoteMeta(source)
	}
	pattern := `(?i)\b(` + strings.Join(escaped, `|`) + `)\b`
	return regexp.MustCompile(pattern)
}

// NewrelicNrqlGapFillingRule checks if 'fill_option' and 'fill_value' are correctly set for intermittent data sources
type NewrelicNrqlGapFillingRule struct {
	tflint.DefaultRule
}

func InitNewrelicNrqlGapFillingRule() *NewrelicNrqlGapFillingRule {
	return &NewrelicNrqlGapFillingRule{}
}

func (r *NewrelicNrqlGapFillingRule) Name() string {
	return "newrelic_nrql_gap_filling"
}

func (r *NewrelicNrqlGapFillingRule) Enabled() bool {
	return true
}

func (r *NewrelicNrqlGapFillingRule) Severity() tflint.Severity {
	return tflint.ERROR
}

func (r *NewrelicNrqlGapFillingRule) Link() string {
	return "slab/github"
}

func (r *NewrelicNrqlGapFillingRule) Check(runner tflint.Runner) error {
	intermittentDataSourcesRegex := getIntermittentRegex()

	schema := &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "fill_option"},
			{Name: "fill_value"},
		},
		Blocks: []hclext.BlockSchema{
			{
				Type: "nrql",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "query"},
					},
				},
			},
		},
	}

	resources, err := runner.GetResourceContent("newrelic_nrql_alert_condition", schema, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		var nrqlBlock *hclext.Block
		for _, block := range resource.Body.Blocks {
			if block.Type == "nrql" {
				nrqlBlock = block
				break
			}
		}

		if nrqlBlock == nil {
			continue
		}

		queryAttr, exists := nrqlBlock.Body.Attributes["query"]
		if !exists {
			runner.EmitIssue(
				r,
				"`nrql.query` is missing in `newrelic_nrql_alert_condition`.",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(queryAttr.Expr, func(query string) error {
			if !intermittentDataSourcesRegex.MatchString(query) {
				return nil
			}

			matched := intermittentDataSourcesRegex.FindString(query)

			fillOptionAttr, hasFillOption := resource.Body.Attributes["fill_option"]
			if !hasFillOption {
				return runner.EmitIssue(
					r,
					fmt.Sprintf("`fill_option` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", matched),
					queryAttr.Expr.Range(),
				)
			}

			return runner.EvaluateExpr(fillOptionAttr.Expr, func(fillOption string) error {
				switch fillOption {
				case "none":
					return runner.EmitIssue(
						r,
						fmt.Sprintf("`fill_option` should not be 'none' when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`. Consider 'last_value' or 'static'.", matched),
						fillOptionAttr.Expr.Range(),
					)
				case "static":
					if _, hasFillValue := resource.Body.Attributes["fill_value"]; !hasFillValue {
						return runner.EmitIssue(
							r,
							"`fill_value` must be set when `fill_option` is 'static' for `newrelic_nrql_alert_condition`.",
							fillOptionAttr.Expr.Range(),
						)
					}
				}
				return nil
			}, nil)
		}, nil)

		if err != nil {
			return err
		}
	}

	return nil
}

// NewrelicSignalLossRule Signal Loss Expiration
// In cases where we expect to lose signal for a while, we should configure expiration
type NewrelicSignalLossRule struct {
	tflint.DefaultRule
}

func InitNewrelicSignalLossRule() *NewrelicSignalLossRule {
	return &NewrelicSignalLossRule{}
}

func (r *NewrelicSignalLossRule) Name() string {
	return "newrelic_nrql_signal_loss"
}

func (r *NewrelicSignalLossRule) Enabled() bool {
	return true
}

func (r *NewrelicSignalLossRule) Severity() tflint.Severity {
	return tflint.ERROR
}

func (r *NewrelicSignalLossRule) Link() string {
	return "slab/github"
}

func (r *NewrelicSignalLossRule) Check(runner tflint.Runner) error {
	intermittentDataSourcesRegex := getIntermittentRegex()

	schema := &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "close_violations_on_expiration"},
			{Name: "ignore_on_expected_termination"},
		},
		Blocks: []hclext.BlockSchema{
			{
				Type: "nrql",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "query"},
					},
				},
			},
		},
	}

	resources, err := runner.GetResourceContent("newrelic_nrql_alert_condition", schema, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		var nrqlBlock *hclext.Block
		for _, block := range resource.Body.Blocks {
			if block.Type == "nrql" {
				nrqlBlock = block
				break
			}
		}

		if nrqlBlock == nil {
			continue
		}

		queryAttr, exists := nrqlBlock.Body.Attributes["query"]
		if !exists {
			runner.EmitIssue(
				r,
				"`nrql.query` is missing in `newrelic_nrql_alert_condition`.",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(queryAttr.Expr, func(query string) error {
			if !intermittentDataSourcesRegex.MatchString(query) {
				return nil
			}

			matched := intermittentDataSourcesRegex.FindString(query)

			if resource.Body.Attributes["ignore_on_expected_termination"] == nil {
				return runner.EmitIssue(
					r,
					fmt.Sprintf("`ignore_on_expected_termination` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", matched),
					queryAttr.Expr.Range(),
				)
			}

			if resource.Body.Attributes["ignore_on_expected_termination"] == nil {
				return runner.EmitIssue(
					r,
					fmt.Sprintf("`ignore_on_expected_termination` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", matched),
					queryAttr.Expr.Range(),
				)
			} else if resource.Body.Attributes["close_violations_on_expiration"] == nil {
				return runner.EmitIssue(
					r,
					fmt.Sprintf("`close_violations_on_expiration` must be set when using intermittent data sources like '%s' in `newrelic_nrql_alert_condition`.", matched),
					queryAttr.Expr.Range(),
				)
			}
			return nil
		}, nil)

		if err != nil {
			return err
		}
	}

	return nil
}
