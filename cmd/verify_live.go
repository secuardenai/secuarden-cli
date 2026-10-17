package cmd

import (
	"fmt"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/live"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/scope"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

const liveGuidance = "Hook trust and client activation are not verified. If configuration may not have loaded: save work and finish active tasks, reload/restart the relevant client, start a new conversation in the intended repository, review hook approval prompts if presented, then repeat verification. Stale configuration is only a possible cause."

func init() {
	var repo, name, client, session string
	var wait time.Duration
	c := &cobra.Command{Use: "verify-live", Short: "Verify a fresh agent tool round-trip persisted locally", Args: cobra.NoArgs,
		Long: "Without --session, arm a 15-minute verification window before starting a new conversation. Then rerun with its exact --session ID. Only persisted pre/post events with the same invocation and tool count. Client surface cannot currently be independently established; results never certify VS Code or desktop specifically.",
		RunE: func(cmd *cobra.Command, _ []string) error { return runLive(cmd, repo, name, client, session, wait) }}
	c.Flags().StringVar(&repo, "repo", "", "Intended Git repository (required)")
	c.Flags().StringVar(&name, "agent", "", "codex or claude-code (required)")
	c.Flags().StringVar(&client, "client", "unknown", "Intended surface: vscode, desktop, cli, or unknown (user declaration only)")
	c.Flags().StringVar(&session, "session", "", "Exact fresh session ID from the intended client")
	c.Flags().DurationVar(&wait, "wait", 0, "Bounded wait for persisted evidence (0 to 5m; default returns immediately)")
	_ = c.MarkFlagRequired("repo")
	_ = c.MarkFlagRequired("agent")
	rootCmd.AddCommand(c)
}

func liveConfiguration(name string) (string, string, error) {
	if err := agent.ValidateLiveHooks(name); err != nil {
		return "", "", err
	}
	if name == "codex" {
		status := agent.InspectCodex()
		if status.State != agent.CodexHookEnabled {
			return "", status.Version, fmt.Errorf("hook configuration missing, disabled, or unsupported (%s); %s", status.State, status.Reason)
		}
		fp, err := agent.HookFingerprint(name)
		return fp, status.Version, err
	}
	fp, err := agent.HookFingerprint(name)
	return fp, "", err
}

func runLive(cmd *cobra.Command, repo, name, client, session string, wait time.Duration) error {
	if name != "codex" && name != "claude-code" {
		return fmt.Errorf("--agent must be codex or claude-code")
	}
	if client != "unknown" && client != "vscode" && client != "desktop" && client != "cli" {
		return fmt.Errorf("invalid --client")
	}
	if wait < 0 || wait > 5*time.Minute {
		return fmt.Errorf("--wait must be between 0 and 5m")
	}
	r, err := repository.ResolveCurrent(repo)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if decision := scope.Evaluate(cfg, r.Root); !decision.Allowed {
		fmt.Fprintf(cmd.OutOrStdout(), "Live verification pending: action excluded by capture scope (%s). Scope has not been changed.\n", decision.Reason)
		return nil
	}
	fp, runtime, err := liveConfiguration(name)
	if err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Live verification pending: %v\n%s\n", err, liveGuidance)
		return nil
	}
	path, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(path)
	if err != nil {
		return fmt.Errorf("capture/persistence storage unavailable: %w", err)
	}
	defer db.Close()
	key := live.Key(name, r.Root)
	if session == "" {
		mark, err := db.LiveWatermark()
		if err != nil {
			return err
		}
		s := live.State{Started: time.Now().UTC(), Watermark: mark, Agent: name, Repository: r.Root, RequestedClient: client, Fingerprint: fp, Runtime: runtime, CLIVersion: Version, Stage: "pending"}
		if err := db.WriteLiveState(key+"_pending", s); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Hooks configured; live verification pending (15-minute window).\nStart a NEW conversation in %s using the intended %s client. Ask the agent to run the harmless command `pwd`. Obtain that conversation's exact session/thread ID from the client or its local session record; do not select an unrelated session from recent activity.\nThen run:\n  secuarden verify-live --repo %q --agent %s --client %s --session <exact-session-id> --wait 60s\nClient surface is user-declared and cannot be independently verified. No prompt/command text is needed.\n%s\n", r.Root, client, r.Root, name, client, liveGuidance)
		return nil
	}
	var s live.State
	found, err := db.ReadLiveState(key+"_pending", &s)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("arm verification first by running without --session")
	}
	if s.Fingerprint != fp || s.Runtime != runtime || s.CLIVersion != Version {
		return fmt.Errorf("verification stale: configuration or detected runtime changed; arm again")
	}
	if s.RequestedClient != client {
		return fmt.Errorf("use the same --client as the armed verification")
	}
	s.Session = session
	deadline := time.Now().Add(wait)
	for {
		if time.Since(s.Started) > 15*time.Minute {
			return fmt.Errorf("verification window expired; arm again and start a new conversation")
		}
		records, old, failures, err := db.LiveEvidence(s.Watermark, session, name)
		if err != nil {
			return fmt.Errorf("capture/persistence read failure: %w", err)
		}
		s.Stage, s.Evidence, s.AgentVersion = live.Evaluate(s, records, old, failures)
		if s.Stage == "tool_round_trip" {
			current, currentRuntime, err := liveConfiguration(name)
			if err != nil {
				return err
			}
			if current != fp || currentRuntime != runtime {
				return fmt.Errorf("configuration or runtime changed during verification; arm again")
			}
			now := time.Now().UTC()
			s.VerifiedAt = &now
			if err := db.WriteLiveState(key, s); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Last verified: %s · %s · session %s · %s\nPersisted tool request and corresponding result observed. Client surface unknown: intended %s is NOT independently verified. This does not verify tool success, hash integrity, repository baseline, or SaaS delivery.\n", now.Format(time.RFC3339), name, session, r.Root, client)
			return nil
		}
		if !time.Now().Before(deadline) || s.Stage == "session_not_fresh" || s.Stage == "capture_persistence_failure" {
			break
		}
		delay := time.Until(deadline)
		if delay > 500*time.Millisecond {
			delay = 500 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-cmd.Context().Done():
			timer.Stop()
			return cmd.Context().Err()
		case <-timer.C:
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Live verification incomplete: %s.\n%s\nFailures before storage opens cannot be attributed from persisted evidence; inspect local hook error logs if needed.\n", s.Stage, liveGuidance)
	return nil
}

func lastLiveLabel(db *storage.DB, name, repo string) (label string) {
	// Scope is current policy, separate from historical verification evidence.
	// Append it even when another diagnostic (such as a missing binary) applies.
	defer func() {
		cfg, err := config.Load()
		if err != nil {
			label += " · current capture scope unavailable"
		} else if decision := scope.Evaluate(cfg, repo); !decision.Allowed {
			label += " · capture currently excluded by scope (" + decision.Reason + ")"
		}
	}()
	var s live.State
	found, err := db.ReadLiveState(live.Key(name, repo), &s)
	if err != nil {
		return name + ": verification state unavailable"
	}
	if !found || s.VerifiedAt == nil {
		if err := agent.ValidateLiveHooks(name); err != nil {
			return name + ": verification pending · " + err.Error()
		}
		return name + ": verification pending"
	}
	fp, runtime, err := liveConfiguration(name)
	label = name + ": last verified " + s.VerifiedAt.Format(time.RFC3339) + " (tool round-trip; client unknown)"
	if err != nil {
		return label + " · STALE: " + err.Error()
	}
	if fp != s.Fingerprint || runtime != s.Runtime || Version != s.CLIVersion {
		label += " · STALE: configuration/executable/runtime changed"
	}
	return label
}
