package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
	"github.com/spf13/cobra"
)

func captureDirectory(cmd *cobra.Command) (string, error) {
	dir, _ := cmd.Flags().GetString("capture-dir")
	if dir != "" {
		return dir, nil
	}
	return observationcapture.DefaultDir()
}
func captureFlag(cmd *cobra.Command) {
	cmd.Flags().String("capture-dir", "", "independent observation inbox (default ~/.secuarden/observations)")
}
func init() {
	hook := &cobra.Command{Use: "observe-codex", Hidden: true, Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {}, RunE: func(cmd *cobra.Command, _ []string) error {
		dir, err := captureDirectory(cmd)
		if err != nil {
			return err
		}
		event, _ := cmd.Flags().GetString("event")
		_, err = observationcapture.Capture(cmd.Context(), dir, event, Version, cmd.InOrStdin())
		if err != nil && !errors.Is(err, observationcapture.ErrDisabled) {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "{}")
		return err
	}}
	captureFlag(hook)
	hook.Flags().String("event", "", "Codex hook event name")
	rootCmd.AddCommand(hook)
	capture := &cobra.Command{Use: "capture", Short: "Opt in to the independent Codex observation inbox"}
	for _, name := range []string{"enable", "disable", "status", "hooks", "trust"} {
		name := name
		child := &cobra.Command{Use: name, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := captureDirectory(cmd)
			if err != nil {
				return err
			}
			switch name {
			case "enable", "disable":
				cfg, err := observationcapture.Configure(dir, name == "enable")
				if err != nil {
					return err
				}
				return writeJSON(cmd.OutOrStdout(), cfg)
			case "hooks":
				executable, err := os.Executable()
				if err != nil {
					return err
				}
				fragment, err := observationcapture.HookDefinitions(executable, dir)
				if err != nil {
					return err
				}
				path, _ := cmd.Flags().GetString("install")
				if path != "" {
					if err := observationcapture.MergeHooks(path, fragment); err != nil {
						return err
					}
				}
				return writeJSON(cmd.OutOrStdout(), fragment)
			case "trust":
				state, _ := cmd.Flags().GetString("state")
				if err := observationcapture.ReportTrust(dir, state); err != nil {
					return err
				}
				if state == "untrusted" {
					store, err := openLedger()
					if err != nil {
						return err
					}
					defer store.Close()
					if err := store.RecordGap(changeledger.CoverageGap{Code: "untrusted_hooks", Source: "operator-report", Detail: "Operator reported untrusted hooks; losses cannot be scoped to a known session."}); err != nil {
						return err
					}
				}
			}
			cfg, err := observationcapture.LoadConfig(dir)
			if err != nil && !errors.Is(err, observationcapture.ErrDisabled) {
				return err
			}
			return writeJSON(cmd.OutOrStdout(), cfg)
		}}
		captureFlag(child)
		if name == "hooks" {
			child.Flags().String("install", "", "explicit hooks.json path to merge into; otherwise print a fragment")
		}
		if name == "trust" {
			child.Flags().String("state", "unknown", "unknown, untrusted, or operator_reported_trusted; does not grant Codex trust")
		}
		capture.AddCommand(child)
	}
	process := &cobra.Command{Use: "process", Short: "Normalize durable observations outside the hook", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		dir, err := captureDirectory(cmd)
		if err != nil {
			return err
		}
		store, err := openLedger()
		if err != nil {
			return err
		}
		defer store.Close()
		limit, _ := cmd.Flags().GetInt("limit")
		result, err := store.ProcessInbox(dir, limit)
		if err != nil {
			return err
		}
		return writeJSON(cmd.OutOrStdout(), result)
	}}
	captureFlag(process)
	process.Flags().Int("limit", 1000, "maximum inputs per batch (1–10000)")
	checkpoint := &cobra.Command{Use: "checkpoint", Short: "Record a current Git checkpoint for an observation session", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		store, err := openLedger()
		if err != nil {
			return err
		}
		defer store.Close()
		repo, _ := cmd.Flags().GetString("repo")
		session, _ := cmd.Flags().GetString("session")
		kind, _ := cmd.Flags().GetString("kind")
		cp, err := store.Checkpoint(repo, session, kind)
		if err != nil {
			return err
		}
		return writeJSON(cmd.OutOrStdout(), cp)
	}}
	checkpoint.Flags().String("repo", ".", "repository directory")
	checkpoint.Flags().String("session", "", "Codex session ID")
	checkpoint.Flags().String("kind", "", "start or end; records current state, never backdated")
	for _, name := range []string{"coverage", "correlate"} {
		name := name
		child := &cobra.Command{Use: name + " DIGEST", Short: "Inspect observation coverage for an exact change", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openLedger()
			if err != nil {
				return err
			}
			defer store.Close()
			var coverage *changeledger.Coverage
			if name == "correlate" {
				session, _ := cmd.Flags().GetString("session")
				since, _ := cmd.Flags().GetString("since")
				until, _ := cmd.Flags().GetString("until")
				a, err := time.Parse(time.RFC3339Nano, since)
				if err != nil {
					return err
				}
				b, err := time.Parse(time.RFC3339Nano, until)
				if err != nil {
					return err
				}
				coverage, err = store.Correlate(args[0], changeledger.ObservationScope{SessionID: session, Since: a, Until: b})
				if err != nil {
					return err
				}
			} else {
				coverage, err = store.Coverage(args[0])
				if err != nil {
					return err
				}
			}
			dir, err := captureDirectory(cmd)
			if err != nil {
				return err
			}
			coverage.InspectInbox(dir)
			jsonOutput, _ := cmd.Flags().GetBool("json")
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), coverage)
			}
			full, _ := cmd.Flags().GetBool("full")
			return renderCoverage(cmd.OutOrStdout(), coverage, full)
		}}
		captureFlag(child)
		child.Flags().Bool("json", false, "emit complete versioned JSON")
		child.Flags().Bool("full", false, "show every inferred link")
		if name == "correlate" {
			child.Flags().String("session", "", "Codex session ID")
			child.Flags().String("since", "", "start of revision window, RFC3339")
			child.Flags().String("until", "", "end of revision window, RFC3339")
		}
		ledgerCmd.AddCommand(child)
	}
	ledgerCmd.AddCommand(capture, process, checkpoint)
}

func renderCoverage(w io.Writer, c *changeledger.Coverage, full bool) error {
	width := sessionSummaryWidth()
	sessionSection(w, "CHANGE COVERAGE", width, false)
	sessionField(w, "Change", c.ChangeDigest, width)
	sessionField(w, "State", c.State, width)
	sessionField(w, "Observations", fmt.Sprintf("%d matched, %d unmatched", c.Matched, c.Unmatched), width)
	sessionField(w, "Deliveries", fmt.Sprintf("%d duplicates, %d conflicts, %d pending", c.Duplicates, c.Conflicts, c.Pending), width)
	sessionSection(w, "COVERAGE REASONS", width, true)
	for _, r := range c.Reasons {
		sessionText(w, "  ", r.Code, width, 0)
		if r.SessionID != "" {
			sessionField(w, "Session", r.SessionID, width)
		}
		sessionText(w, "    ", r.Detail, width, 0)
	}
	sessionSection(w, "INFERRED LINKS", width, true)
	limit := len(c.Links)
	if !full {
		limit = min(limit, 10)
	}
	for _, l := range c.Links[:limit] {
		sessionField(w, l.Confidence, l.Event+" · "+l.ObservationID, width)
		if full {
			for _, e := range l.Evidence {
				sessionText(w, "    ", "Evidence: "+e, width, 0)
			}
			for _, r := range l.Reasons {
				sessionText(w, "    ", "Reason: "+r, width, 0)
			}
		}
	}
	if limit < len(c.Links) {
		sessionText(w, "  ", fmt.Sprintf("%d more links; use --full or --json", len(c.Links)-limit), width, 0)
	}
	return nil
}
