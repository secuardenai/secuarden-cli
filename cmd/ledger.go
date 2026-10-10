package cmd

import (
	"fmt"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/spf13/cobra"
)

var ledgerCmd = &cobra.Command{Use: "ledger", Short: "Build and inspect Git-anchored change records"}
var ledgerBuildCmd = &cobra.Command{Use: "build", Short: "Record an exact Git revision", Args: cobra.NoArgs, RunE: runLedgerBuild}
var ledgerShowCmd = &cobra.Command{Use: "show DIGEST", Short: "Inspect a stored change record", Args: cobra.ExactArgs(1), RunE: runLedgerShow}

var ledgerRepo, ledgerHead, ledgerBase, ledgerBaseRef, ledgerDB string

func init() {
	ledgerBuildCmd.Flags().StringVar(&ledgerRepo, "repo", ".", "repository directory")
	ledgerBuildCmd.Flags().StringVar(&ledgerHead, "head", "HEAD", "head commit or ref")
	ledgerBuildCmd.Flags().StringVar(&ledgerBase, "base", "", "exact base commit or ref")
	ledgerBuildCmd.Flags().StringVar(&ledgerBaseRef, "base-ref", "", "ref whose merge base with head selects the base")
	ledgerBuildCmd.MarkFlagsMutuallyExclusive("base", "base-ref")
	ledgerCmd.PersistentFlags().StringVar(&ledgerDB, "db", "", "ledger database path (default ~/.secuarden/ledger.db)")
	ledgerCmd.AddCommand(ledgerBuildCmd, ledgerShowCmd)
	rootCmd.AddCommand(ledgerCmd)
}

func openLedger() (*changeledger.Store, error) {
	path := ledgerDB
	if path == "" {
		var err error
		path, err = changeledger.DefaultDBPath()
		if err != nil {
			return nil, err
		}
	}
	return changeledger.Open(path)
}

func runLedgerBuild(cmd *cobra.Command, _ []string) error {
	c, err := changeledger.Build(changeledger.BuildOptions{Repository: ledgerRepo, Head: ledgerHead, Base: ledgerBase, BaseRef: ledgerBaseRef})
	if err != nil {
		return err
	}
	if c.Status != "complete" {
		if err := writeJSON(cmd.OutOrStdout(), c); err != nil {
			return err
		}
		return fmt.Errorf("Git revision could not be fully observed; change was not stored")
	}
	store, err := openLedger()
	if err != nil {
		return err
	}
	defer store.Close()
	receipt, err := store.Put(c)
	if err != nil {
		return err
	}
	return writeJSON(cmd.OutOrStdout(), struct {
		Change  *changeledger.Change `json:"change"`
		Receipt changeledger.Receipt `json:"receipt"`
	}{c, receipt})
}

func runLedgerShow(cmd *cobra.Command, args []string) error {
	store, err := openLedger()
	if err != nil {
		return err
	}
	defer store.Close()
	c, receipt, err := store.Get(args[0])
	if err != nil {
		return err
	}
	return writeJSON(cmd.OutOrStdout(), struct {
		Change  *changeledger.Change `json:"change"`
		Receipt changeledger.Receipt `json:"receipt"`
	}{c, receipt})
}
