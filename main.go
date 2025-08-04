package main

import (
	"github.com/livelink/tflint-ruleset-livelink/rules"
	"github.com/terraform-linters/tflint-plugin-sdk/plugin"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: &tflint.BuiltinRuleSet{
			Name:    "livelink",
			Version: "0.1.0",
			Rules: []tflint.Rule{
				rules.InitNewrelicNrqlGapFillingRule(),
				rules.InitNewrelicSignalLossRule(),
			},
		},
	})
}
