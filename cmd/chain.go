package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/chain"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

func newChainCommand() *cobra.Command {
	var repo, base, baseRef, head string
	var asJSON, seal bool
	command := &cobra.Command{
		Use:   "chain",
		Short: "Report the prompt-to-merge chain for a commit range",
		Long: `Join captured prompts, agent edits, and posture findings to the commits
between a merge base and a head.

The local result is a checksum of what this machine recorded. secuarden verify
recomputes that checksum. It does not stop the developer from changing the
local database and recomputing it.

--seal registers a one-time public key and uploads a signature to the Secuarden
service. Tamper-evidence exists only after that service accepts the seal.`,
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runChain(cmd, repo, base, baseRef, head, asJSON, seal)
		},
	}
	command.Flags().StringVar(&repo, "repo", ".", "repository path")
	command.Flags().StringVar(&base, "base", "", "exact base commit")
	command.Flags().StringVar(&baseRef, "base-ref", "", "ref whose merge-base with head selects the base")
	command.Flags().StringVar(&head, "head", "HEAD", "head commit")
	command.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	command.Flags().BoolVar(&seal, "seal", false, "sign the chain and upload it to the Secuarden service")
	command.MarkFlagsMutuallyExclusive("base", "base-ref")
	return command
}

func init() { rootCmd.AddCommand(newChainCommand()) }

func runChain(cmd *cobra.Command, repo, base, baseRef, head string, asJSON, seal bool) error {
	identity, err := repository.ResolveCurrent(repo)
	if err != nil {
		return err
	}
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	report, err := chain.Build(db, identity.Root, base, baseRef, head)
	if err != nil {
		return err
	}
	attestationReport := currentAttestation()
	report.ConfigurationAttestation = &attestationReport
	if attestationReport.Error != "" && seal {
		return fmt.Errorf("cannot seal unreadable configuration history: %s", attestationReport.Error)
	}
	if asJSON && !seal {
		return writeJSON(cmd.OutOrStdout(), report)
	}
	if !asJSON {
		writeChainText(cmd.OutOrStdout(), report)
	}
	if !seal {
		return nil
	}
	cfg, err := config.LoadForRepository(identity.Root)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	sealed, err := chain.SealReport(ctx, cfg, report)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSON(cmd.OutOrStdout(), struct {
			*chain.Report
			Seal *chain.Seal `json:"seal"`
		}{report, sealed})
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nSaaS seal accepted for %s\nkey %s\n", sealed.Digest, sealed.KeyID)
	return nil
}

func writeChainText(w io.Writer, report *chain.Report) {
	fmt.Fprintf(w, "Chain checksum %s..%s\n", shortID(report.Base), shortID(report.Head))
	fmt.Fprintln(w, "Local record of what this machine captured. This is not a SaaS seal.")
	if report.ConfigurationAttestation != nil {
		writeAttestation(w, *report.ConfigurationAttestation)
	}
	if len(report.Entries) == 0 {
		fmt.Fprintln(w, "No captured edits in this repository for the selected range.")
		return
	}
	for _, entry := range report.Entries {
		fmt.Fprintf(w, "\n%s\n", entry.Path)
		if entry.Committed {
			fmt.Fprintf(w, "  commit %s %s\n", shortID(entry.Commit), entry.CommitSubject)
		} else {
			fmt.Fprintln(w, "  not yet committed in this range")
		}
		if entry.PromptCaptured {
			fmt.Fprintf(w, "  prompt: %s\n", entry.Prompt)
		} else {
			fmt.Fprintln(w, "  prompt: not captured")
		}
		if len(entry.Findings) == 0 {
			fmt.Fprintln(w, "  findings: none fired")
			continue
		}
		for _, finding := range entry.Findings {
			fmt.Fprintf(w, "  finding %s: %s\n", finding.Kind, finding.Explanation)
		}
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
