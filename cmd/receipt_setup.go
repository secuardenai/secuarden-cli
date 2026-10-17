package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/changereceipt"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/spf13/cobra"
)

func init() {
	initCmd.Flags().String("receipt-mode", "", "receipt creation: automatic or explicit (preserve existing; otherwise explicit)")
	initCmd.Flags().String("receipt-base-ref", "", "receipt target ref (merge base with pushed head)")
	initCmd.Flags().StringArray("receipt-branch-base", nil, "destination-specific base, e.g. refs/heads/main=origin/release (repeat)")
}
func configureReceiptSetup(cmd *cobra.Command, cfg *config.Config, root string) error {
	integration := cfg.RepositoryIntegrations[root]
	options := integration.Receipt
	mode, _ := cmd.Flags().GetString("receipt-mode")
	if mode == "" {
		mode = options.Mode
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	// Interactive setup offers a choice; scripts retain a deterministic explicit default.
	file, ok := cmd.InOrStdin().(*os.File)
	interactive := false
	if ok {
		if info, err := file.Stat(); err == nil {
			interactive = info.Mode()&os.ModeCharDevice != 0
		}
	}
	if mode == "" && interactive {
		fmt.Fprint(cmd.OutOrStdout(), "Receipt creation [explicit/automatic] (default explicit): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read receipt mode: %w", err)
		}
		mode = strings.TrimSpace(line)
	}
	if mode == "" {
		mode = "explicit"
	}
	if mode != "automatic" && mode != "explicit" {
		return fmt.Errorf("receipt-mode must be automatic or explicit")
	}
	options.Mode = mode
	if cmd.Flags().Changed("receipt-base-ref") {
		options.BaseRef, _ = cmd.Flags().GetString("receipt-base-ref")
	}
	if mode == "automatic" && options.BaseRef == "" {
		suggestion, _ := changereceipt.Git(root, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
		if interactive {
			fmt.Fprintf(cmd.OutOrStdout(), "Receipt target ref [%s]: ", suggestion)
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			options.BaseRef = strings.TrimSpace(line)
			if options.BaseRef == "" {
				options.BaseRef = suggestion
			}
		} else {
			options.BaseRef = suggestion
		}
	}
	if mode == "automatic" {
		if options.BaseRef == "" {
			return fmt.Errorf("automatic receipts require --receipt-base-ref")
		}
		if _, err := changereceipt.Git(root, "rev-parse", "--verify", "--end-of-options", options.BaseRef+"^{commit}"); err != nil {
			return fmt.Errorf("receipt-base-ref must resolve to a locally available commit")
		}
	}
	overrides, _ := cmd.Flags().GetStringArray("receipt-branch-base")
	for _, value := range overrides {
		dest, base, ok := strings.Cut(value, "=")
		if !ok || !strings.HasPrefix(dest, "refs/heads/") || base == "" {
			return fmt.Errorf("receipt-branch-base requires refs/heads/BRANCH=REF")
		}
		if _, err := changereceipt.Git(root, "check-ref-format", dest); err != nil {
			return fmt.Errorf("invalid receipt destination ref")
		}
		if _, err := changereceipt.Git(root, "rev-parse", "--verify", "--end-of-options", base+"^{commit}"); err != nil {
			return fmt.Errorf("receipt branch base unavailable")
		}
		if options.BranchBases == nil {
			options.BranchBases = map[string]string{}
		}
		options.BranchBases[dest] = base
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if err = changereceipt.ConfigureHook(root, binary, mode); err != nil {
		return err
	}
	integration.Receipt = options
	cfg.RepositoryIntegrations[root] = integration
	fmt.Fprintf(cmd.OutOrStdout(), "Receipt creation: %s\n", mode)
	return nil
}
