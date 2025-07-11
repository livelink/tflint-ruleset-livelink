package rules

import (
	"fmt"
	"regexp"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// NewrelicNrqlGapFillingRule checks if 'fill_option' and 'fill_value' are correctly set for intermittent data sources
type NewrelicNrqlGapFillingRule struct {
	tflint.DefaultRule
}

func NewNewrelicNrqlGapFillingRule() *NewrelicNrqlGapFillingRule {
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
	intermittentDataSourcesRegex := regexp.MustCompile(`(?i)\bTransactionError\b`)

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
