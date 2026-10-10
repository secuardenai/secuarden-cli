package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/identity"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var (
	initSyncAPIKey       string
	initSyncAPIURL       string
	initAgent            string
	initScope            string
	initApproveRepo      bool
	initEnableCodexHooks bool
	initRepo             string
)

func init() {
	initCmd.Flags().StringVar(&initRepo, "repo", "", "Explicit Git repository to configure (required; use . for the current repository)")
	_ = initCmd.MarkFlagRequired("repo")
	initCmd.Flags().StringVar(&initSyncAPIKey, "api-key", "", "Secuarden API key for this repository only — enables SaaS sync")
	initCmd.Flags().StringVar(&initSyncAPIURL, "api-url", "", "SaaS server URL for this repository only (default: https://app.secuarden.ai)")
	initCmd.Flags().StringVar(&initAgent, "agent", "auto", "Agent to configure: auto, claude-code, or codex")
	initCmd.Flags().BoolVar(&initEnableCodexHooks, "enable-codex-hooks", false, "Explicitly enable the Codex hooks feature in ~/.codex/config.toml")
	initCmd.Flags().StringVar(&initScope, "scope", "", "Capture scope: all, repo, or approved (default: preserve existing, otherwise all)")
	initCmd.Flags().BoolVar(&initApproveRepo, "add-approved-repo", false, "Add the current Git repository to the approved scope allowlist")
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Install Secuarden hooks and create the local database",
	Long: `Install Secuarden hooks into supported AI coding agents and create the local SQLite database.

Per-repository setup is required. Always pass --repo PATH explicitly, even inside
a Git repository. Use --repo . to select the current repository.
API keys and server URLs are stored in ~/.secuarden/config.json by canonical
repository path, never in the worktree. User-wide API keys are not a fallback;
configure each repository explicitly. Omitting --api-key preserves an existing
repository integration; a new repository stays local-only. --api-url configures
the server for this repository (default https://app.secuarden.ai).

By default all data stays local. Pass --api-key to enable SaaS sync: at the
	end of every supported agent session the session summary is posted to Secuarden
and a risk evaluation is printed in the terminal before the agent exits.

Agent selection:
  --agent auto        configure detected supported agents (default)
  --agent claude-code configure Claude Code
  --agent codex       configure Codex only when its CLI and config support hooks
  --enable-codex-hooks explicitly enable Codex hooks in ~/.codex/config.toml

Capture scope:
  --scope all         capture supported sessions for this OS user (default)
  --scope repo        capture only the repository where init is run
  --scope approved    capture only repositories in the allowlist
  --add-approved-repo add the current repository and select approved scope

Codex being installed is not sufficient for integration. Secuarden validates
the installed CLI, its version, hook feature, configuration, and project
trust. Use --enable-codex-hooks only when you explicitly want Secuarden to
update the Codex feature setting; otherwise init prints the manual guidance.

When --agent auto finds no supported agent in an interactive terminal, init
offers Claude Code or Codex as explicit choices. In scripts, pass --agent
claude-code or --agent codex directly. If a VS Code Codex extension is found
with hooks disabled, init asks once whether to enable them.

  secuarden init --repo .                  # local only
  secuarden init --repo . --api-key sec_xxxx # SaaS sync for this repository
  secuarden init --repo /path/to/repo --api-key sec_xxxx --api-url https://dev.example`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	// Resolve the required repository before modifying agent or user settings.
	if strings.TrimSpace(initRepo) == "" {
		return fmt.Errorf("--repo PATH is required; use `secuarden init --repo .` to explicitly select the current repository")
	}
	setupRepository, err := repository.ResolveCurrent(initRepo)
	if err != nil {
		return fmt.Errorf("per-repository setup requires a Git repository; pass --repo PATH: %w", err)
	}
	if binary, err := os.Executable(); err == nil {
		if found, err := exec.LookPath("secuarden"); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Secuarden is not on terminal PATH. Add %s to PATH in your shell configuration. Hooks will use the absolute binary path.\n", filepath.Dir(binary))
		} else if absolute, _ := filepath.Abs(found); absolute != binary {
			fmt.Fprintf(cmd.OutOrStdout(), "Terminal PATH selects %s; hooks will use %s.\n", absolute, binary)
		}
	}
	// 1. Detect supported agents
	requestedAgent := strings.ToLower(strings.TrimSpace(initAgent))
	claudeDetection := agent.DetectClaudeCode()
	claudeDetected := claudeDetection.Found
	codexExtension := agent.DetectCodexVSCode()
	codexStatus := agent.InspectCodex()
	codexDetected := codexStatus.State == agent.CodexHookEnabled
	if requestedAgent != "auto" && requestedAgent != "claude-code" && requestedAgent != "codex" {
		return fmt.Errorf("invalid --agent %q: choose auto, claude-code, or codex", initAgent)
	}
	if codexExtension.Found && !codexDetected {
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Codex VS Code extension detected (%s), but Codex capability is %s\n", codexExtension.Path, codexStatus.State)
	}
	if !initEnableCodexHooks && codexExtension.Found && codexStatus.State == agent.CodexHookDisabled && (requestedAgent == "auto" || requestedAgent == "codex") {
		if interactiveTerminal() {
			enable, err := promptEnableCodexHooks(cmd.OutOrStdout(), cmd.InOrStdin())
			if err != nil {
				return err
			}
			if enable {
				if err := agent.EnableCodexHooks(); err != nil {
					return fmt.Errorf("enable Codex hooks: %w", err)
				}
				codexStatus = agent.InspectCodex()
				codexDetected = codexStatus.State == agent.CodexHookEnabled
			}
		}
	}
	if requestedAgent == "auto" && !claudeDetected && !codexDetected {
		selected, err := promptForAgent(cmd.OutOrStdout(), cmd.InOrStdin())
		if err != nil {
			return err
		}
		requestedAgent = selected
	}
	claudeInstalled := claudeDetected && (requestedAgent == "auto" || requestedAgent == "claude-code")
	codexInstalled := codexDetected && (requestedAgent == "auto" || requestedAgent == "codex")
	if requestedAgent == "claude-code" && !claudeDetected {
		return fmt.Errorf("Claude Code was requested but no shared settings file or supported VS Code extension was detected; install the Claude Code VS Code extension and rerun init, or use --agent claude-code after confirming the extension is installed")
	}
	if initEnableCodexHooks && (requestedAgent == "codex" || requestedAgent == "auto") {
		switch codexStatus.State {
		case agent.CodexHookDisabled:
			if err := agent.EnableCodexHooks(); err != nil {
				return fmt.Errorf("enable Codex hooks: %w", err)
			}
			codexStatus = agent.InspectCodex()
			codexDetected = codexStatus.State == agent.CodexHookEnabled
		case agent.CodexHookUntrusted:
			return fmt.Errorf("Codex is untrusted: %s; trust the current project in Codex before enabling hooks", codexStatus.Reason)
		}
	}
	if requestedAgent == "codex" && !codexDetected {
		return fmt.Errorf("Codex cannot be configured (%s): %s%s", codexStatus.State, codexStatus.Reason, codexSetupGuidance(codexStatus, codexExtension))
	}
	if !claudeInstalled && !codexInstalled {
		return fmt.Errorf("no supported AI coding agent detected; Claude Code settings or a supported Codex hook feature are required%s", codexSetupGuidance(codexStatus, codexExtension))
	}
	if claudeInstalled {
		fmt.Printf("✓ Claude Code detected (%s)\n", claudeDetection.Source)
	}
	if codexExtension.Found {
		fmt.Printf("✓ Codex VS Code extension detected (%s)\n", codexExtension.Path)
	}
	if codexInstalled {
		fmt.Printf("✓ Codex detected (%s, %s)\n", codexStatus.Version, codexStatus.Feature)
	}

	// 2. Resolve and save configuration (before InstallHooks so hooks can read it).
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cmd.Flags().Changed("scope") {
		cfg.CaptureScope = strings.ToLower(strings.TrimSpace(initScope))
	}
	if cfg.CaptureScope == "" {
		cfg.CaptureScope = config.CaptureScopeAll
	}
	if cfg.CaptureScope != config.CaptureScopeAll && cfg.CaptureScope != config.CaptureScopeRepo && cfg.CaptureScope != config.CaptureScopeApproved {
		return fmt.Errorf("invalid --scope %q: choose all, repo, or approved", initScope)
	}
	if initApproveRepo {
		if cmd.Flags().Changed("scope") && cfg.CaptureScope != config.CaptureScopeApproved {
			return fmt.Errorf("--add-approved-repo requires --scope approved when --scope is provided")
		}
		cfg.CaptureScope = config.CaptureScopeApproved
	}
	if cfg.CaptureScope == config.CaptureScopeRepo || initApproveRepo {
		current, err := repository.ResolveCurrent(setupRepository.Root)
		if err != nil || !current.RootValid {
			return fmt.Errorf("capture scope %q requires initialization inside a Git repository", cfg.CaptureScope)
		}
		if cfg.CaptureScope == config.CaptureScopeRepo {
			cfg.RepositoryRoot = current.Root
		}
		if initApproveRepo {
			cfg.ApprovedRepositories = append(cfg.ApprovedRepositories, current.Root)
		}
	}
	if cfg.CaptureScope != config.CaptureScopeRepo {
		cfg.RepositoryRoot = ""
	}
	if _, err := config.ConfigureIntegration(cfg, setupRepository.Root, initSyncAPIKey, initSyncAPIURL); err != nil {
		return err
	}
	if err := configureReceiptSetup(cmd, cfg, setupRepository.Root); err != nil {
		return err
	}
	syncEnabled := cfg.RepositoryIntegrations[setupRepository.Root].SyncEnabled
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if syncEnabled {
		fmt.Printf("✓ SaaS sync enabled for %s — session feedback will appear in terminal\n", setupRepository.Root)
	} else {
		fmt.Println("✓ Local-only mode (pass --api-key to enable SaaS sync)")
	}

	// 3. Back up and merge hooks
	if claudeInstalled {
		if err := agent.InstallHooks(); err != nil {
			return fmt.Errorf("install Claude Code hooks: %w", err)
		}
		fmt.Println("✓ Claude Code hooks installed")
	}
	if codexInstalled {
		if err := agent.InstallCodexHooks(); err != nil {
			return fmt.Errorf("install Codex hooks: %w", err)
		}
		fmt.Println("✓ Codex hooks installed")
	}
	fmt.Println("✓ Secuarden hooks installed for this OS user")
	fmt.Printf("  Capture scope: %s\n", captureScopeDescription(cfg))
	configPath, _ := config.DefaultConfigPath()
	fmt.Printf("  Configuration: %s\n", homeRelative(configPath))
	fmt.Printf("  Local database: %s\n", homeRelative(filepathForDisplay()))
	if syncEnabled {
		fmt.Println("  Cloud sync: enabled")
	} else {
		fmt.Println("  Cloud sync: disabled")
	}
	fmt.Println("  Scope applies to the current OS user.")

	// 4. Create database
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return fmt.Errorf("db path: %w", err)
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	db.Close()
	fmt.Printf("✓ Database created at %s\n", dbPath)

	// 5. Capture developer identity
	dev := identity.Capture()
	if dev.Email != "" || dev.Name != "" {
		name := dev.Name
		if name == "" {
			name = dev.OSUser
		}
		fmt.Printf("✓ Developer identity: %s <%s>\n", name, dev.Email)
	}

	fmt.Println()
	fmt.Println("Secuarden is ready. After your next AI coding session, run:")
	fmt.Println("  secuarden status")
	return nil
}

func codexSetupGuidance(status agent.CodexStatus, extension agent.Detection) string {
	detected := ""
	if extension.Found {
		detected = "\nDetected the Codex VS Code extension at " + extension.Path + "."
	}
	switch status.State {
	case agent.CodexHookDisabled:
		return detected + "\nEnable it with `secuarden init --repo . --agent codex --enable-codex-hooks`, or enable the feature manually in " + status.ConfigPath + "."
	case agent.CodexHookUnavailable:
		if extension.Found {
			return detected + "\nIts bundled runtime cannot yet be validated by Secuarden. Install the standalone Codex CLI or use the VS Code Codex integration after hook-runtime support is available."
		}
		return detected + "\nInstall Codex and ensure `codex` is on PATH."
	case agent.CodexHookUntrusted:
		return detected + "\nTrust the current project in Codex before enabling hooks."
	case agent.CodexHookUnsupported:
		return detected + "\nUpgrade to a Codex CLI that advertises the hooks feature and hook trust."
	default:
		return detected
	}
}

func promptForAgent(out io.Writer, in io.Reader) (string, error) {
	fmt.Fprintln(out, "No supported AI coding agent was detected.")
	fmt.Fprintln(out, "Which coding agent are you using?")
	fmt.Fprintln(out, "  1. Claude Code (VS Code extension)")
	fmt.Fprintln(out, "  2. Codex (VS Code extension)")
	fmt.Fprintln(out, "  Other IDE integrations are not currently guaranteed to work seamlessly.")
	fmt.Fprint(out, "Select 1 or 2: ")

	if !interactiveTerminal() {
		return "", fmt.Errorf("agent selection requires an interactive terminal; rerun with `--agent claude-code` or `--agent codex`")
	}
	choice, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && len(choice) == 0 {
		return "", fmt.Errorf("read agent selection: %w", err)
	}
	switch strings.TrimSpace(choice) {
	case "1":
		return "claude-code", nil
	case "2":
		return "codex", nil
	default:
		return "", fmt.Errorf("invalid selection %q; rerun and choose 1 or 2, or pass --agent explicitly", strings.TrimSpace(choice))
	}
}

func interactiveTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func promptEnableCodexHooks(out io.Writer, in io.Reader) (bool, error) {
	fmt.Fprint(out, "Enable Codex hooks for the detected VS Code extension? [Y/n]: ")
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, fmt.Errorf("read Codex hook choice: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid choice %q; rerun and answer yes or no", strings.TrimSpace(answer))
	}
}

func captureScopeDescription(cfg *config.Config) string {
	switch cfg.CaptureScope {
	case config.CaptureScopeRepo:
		return "this repository only (" + homeRelative(cfg.RepositoryRoot) + ")"
	case config.CaptureScopeApproved:
		return fmt.Sprintf("approved repositories only (%d configured)", len(cfg.ApprovedRepositories))
	default:
		return "all supported projects for this OS user"
	}
}

func filepathForDisplay() string {
	path, err := storage.DefaultDBPath()
	if err != nil {
		return "~/.secuarden/secuarden.db"
	}
	return path
}
