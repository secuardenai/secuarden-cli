package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/attestation"
	"github.com/secuardenai/secuarden-cli/internal/capturecontract"
	"github.com/spf13/cobra"
)

func currentAttestation() attestation.Report {
	return attestation.Current(agent.ObserveCaptureConfiguration, true)
}
func writeAttestation(w io.Writer, r attestation.Report) {
	fmt.Fprintln(w, "Capture configuration attestation (OS-user scope)")
	fmt.Fprintln(w, r.Summary())
	if r.Error != "" {
		fmt.Fprintln(w, "Error:", r.Error)
	}
	if r.State != nil {
		for _, contract := range r.State.Contracts {
			fmt.Fprintf(w, "Contract: %s v%s (%s)\n", contract.Adapter, contract.Version, contract.Digest)
		}
		for _, result := range r.State.Results {
			fmt.Fprintf(w, "  %s: %s %s\n", terminalCell(result.ID), result.Status, terminalCell(result.Reason))
		}
		fmt.Fprintf(w, "Last observed: %s; last matching: %s\n", r.State.LastObserved.Format(time.RFC3339), r.State.LastMatching.Format(time.RFC3339))
	}
	for _, event := range r.History {
		fmt.Fprintf(w, "  %s  %s", event.At.Format(time.RFC3339), event.Kind)
		if !event.PreviousObservation.IsZero() {
			fmt.Fprintf(w, " (previous observation %s)", event.PreviousObservation.Format(time.RFC3339))
		}
		for _, difference := range event.State.Differences {
			fmt.Fprintf(w, " · %s", terminalCell(difference))
		}
		if event.Reason != "" {
			fmt.Fprintf(w, " · %s", terminalCell(event.Reason))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, r.Limitation)
}
func newAttestationCommand() *cobra.Command {
	parent := &cobra.Command{SilenceErrors: true, Use: "attestation", Short: "Check embedded capture contracts and inspect observation history"}
	for _, action := range []string{"enable", "disable", "check", "status", "history", "verify"} {
		action := action
		var names []string

		var asJSON bool
		c := &cobra.Command{Use: action, Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
			var report attestation.Report
			if action == "status" || action == "history" || action == "verify" {
				report = attestation.Current(agent.ObserveCaptureConfiguration, action != "verify")
			} else {
				path, err := attestation.DefaultPath()
				if err != nil {
					return err
				}
				store, err := attestation.Open(path)
				if err != nil {
					return err
				}
				defer store.Close()
				if len(names) == 0 {
					if agent.HooksInstalled() {
						names = append(names, "claude-code")
					}
					if agent.CodexHooksInstalled() {
						names = append(names, "codex")
					}
				}
				report, err = store.Apply(action, names, "", time.Now(), agent.ObserveCaptureConfiguration)
				if err != nil {
					return err
				}
			}
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), report); err != nil {
					return err
				}
			} else {
				writeAttestation(cmd.OutOrStdout(), report)
			}
			if report.Error != "" {
				return fmt.Errorf("attestation unavailable: %s", report.Error)
			}
			if (action == "check" || action == "enable") && report.Status != "satisfied" {
				if report.Status == "not_configured" {
					return fmt.Errorf("configuration attestation is not configured for this OS user; run `secuarden attestation enable` (or specify `--agent claude-code` or `--agent codex`)")
				}
				return fmt.Errorf("configuration attestation: %s", report.Status)
			}
			if action == "verify" && report.Head == "" {
				return fmt.Errorf("no attestation history to verify")
			}
			return nil
		}}
		c.Flags().BoolVar(&asJSON, "json", false, "emit structured configuration state and full transition history")
		if action == "enable" {
			c.Flags().StringSliceVar(&names, "agent", nil, "agents: claude-code,codex (default: installed agents)")
		}
		c.SilenceErrors = true
		parent.AddCommand(c)
	}
	parent.AddCommand(&cobra.Command{SilenceErrors: true, Use: "contracts", Short: "Show the capture contracts embedded in this CLI", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		contracts := []capturecontract.Contract{}
		for _, name := range []string{"claude-code", "codex"} {
			c, _ := capturecontract.For(name)
			contracts = append(contracts, c)
		}
		return writeJSON(cmd.OutOrStdout(), contracts)
	}})
	parent.AddCommand(&cobra.Command{SilenceErrors: true, Use: "baseline", Hidden: true, DisableFlagParsing: true, RunE: func(cmd *cobra.Command, _ []string) error {
		return fmt.Errorf("capture contracts are embedded in the CLI; baseline replacement is no longer supported")
	}})
	var interval time.Duration
	watch := &cobra.Command{SilenceErrors: true, Use: "watch", Short: "Observe independently of agent hooks until interrupted", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if interval < time.Second || interval > 30*time.Second {
			return fmt.Errorf("interval must be between 1s and 30s")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		fmt.Fprintln(cmd.OutOrStdout(), "Observing configuration independently of hooks; stop with Ctrl+C. Changes between checks may be missed.")
		for {
			r := currentAttestation()
			if r.Error != "" {
				return fmt.Errorf("attestation: %s", r.Error)
			}
			if r.Status == "not_configured" {
				return fmt.Errorf("run secuarden attestation enable first")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}}
	watch.Flags().DurationVar(&interval, "interval", 15*time.Second, "poll interval (1s–30s); gaps over 90s are recorded")
	parent.AddCommand(watch)
	return parent
}
func init() { rootCmd.AddCommand(newAttestationCommand()) }

// Setup defaults on only once. A previous explicit disable survives reinitialization.
func initializeAttestation(enabled bool, explicit bool) error {
	path, err := attestation.DefaultPath()
	if err != nil {
		return err
	}
	if !explicit {
		if _, err := os.Stat(path); err == nil {
			r := currentAttestation()
			if r.Error != "" {
				return fmt.Errorf("%s", r.Error)
			}
			if r.State != nil && !r.State.Enabled {
				return nil
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	s, err := attestation.Open(path)
	if err != nil {
		return err
	}
	defer s.Close()
	names := []string{}
	if agent.HooksInstalled() {
		names = append(names, "claude-code")
	}
	if agent.CodexHooksInstalled() {
		names = append(names, "codex")
	}
	action := "enable"
	if !enabled {
		action = "disable"
	}
	r, err := s.Apply(action, names, "installation setup", time.Now(), agent.ObserveCaptureConfiguration)
	if err == nil && enabled && r.Status != "satisfied" {
		return fmt.Errorf("capture contract %s: %v", r.Status, r.State.Differences)
	}
	return err
}
