package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/secuardenai/secuarden-cli/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCommand() *cobra.Command {
	parent := &cobra.Command{Use: "policy", Short: "Import and list local enforcement policies (v0.1)"}
	var file string
	upload := &cobra.Command{Use: "upload --file policies.json", Short: "Validate and immediately activate local policies", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		count, skipped, err := policy.Import(file)
		for _, reason := range skipped {
			fmt.Fprintln(cmd.OutOrStdout(), "Skipped:", reason)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Imported and activated %d policies; skipped %d.\n", count, len(skipped))
		if count == 0 {
			return fmt.Errorf("no policies imported")
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Active for this OS user on the next synchronous pre-tool hook. Requires current Secuarden hooks and python3. Shell/unsupported tools are blocked in v0.1.")
		return listPolicies(cmd)
	}}
	upload.Flags().StringVar(&file, "file", "", "JSON policy bundle path")
	_ = upload.MarkFlagRequired("file")
	list := &cobra.Command{Use: "list", Short: "List active policies in the local instance", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return listPolicies(cmd) }}
	parent.AddCommand(upload, list)
	return parent
}

func listPolicies(cmd *cobra.Command) error {
	policies, err := policy.Load()
	if err != nil {
		return err
	}
	if policies == nil {
		policies = []policy.Policy{}
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(policy.Bundle{Version: "0.1", Policies: policies})
}

func init() { rootCmd.AddCommand(newPolicyCommand()) }
