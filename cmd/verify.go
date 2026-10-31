package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var verifyCmd = newVerifyCommand()

type verifyOptions struct {
	repo               string
	all, json, details bool
}

type verificationReport struct {
	*storage.IntegrityResult
	Status     string `json:"status"`
	Scope      string `json:"scope"`
	Repository string `json:"repository,omitempty"`
	Storage    string `json:"storage"`
}

func newVerifyCommand() *cobra.Command {
	var options verifyOptions
	c := &cobra.Command{
		Use: "verify", Short: "Verify the stored audit trail for a repository",
		Long: "Verify complete stored session chains for the current Git repository. Use --repo <path> to select another repository, or --all for the entire local audit database. Repositories are matched by canonical Git remote identity (including other clones/worktrees), with local path identity for repositories without a remote. This does not check current source files or live hook delivery.",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return runVerify(cmd, options) },
	}
	c.Flags().StringVar(&options.repo, "repo", "", "path inside the Git repository to verify")
	c.Flags().BoolVar(&options.all, "all", false, "verify all local repositories")
	c.Flags().BoolVar(&options.json, "json", false, "emit complete structured findings as JSON")
	c.Flags().BoolVar(&options.details, "details", false, "show all affected sessions and individual findings")
	c.MarkFlagsMutuallyExclusive("repo", "all")
	c.MarkFlagsMutuallyExclusive("json", "details")
	return c
}

func runVerify(cmd *cobra.Command, options verifyOptions) error {
	var selected repository.Identity
	var err error
	if !options.all {
		selected, err = repository.ResolveCurrent(options.repo)
		if err != nil {
			return fmt.Errorf("cannot determine verification repository: %w; use --repo <path> or --all", err)
		}
	}
	path, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(path)
	if err != nil {
		return fmt.Errorf("open audit storage: %w", err)
	}
	defer db.Close()
	refs, err := db.ListSessionRepositories()
	if err != nil {
		return err
	}
	captured := make([]repository.CapturedRef, 0, len(refs))
	for _, ref := range refs {
		captured = append(captured, repository.CapturedRef{SessionID: ref.SessionID, GitRepoURL: ref.GitRepoURL, WorkingDirectory: ref.WorkingDirectory})
	}
	groups := repository.GroupCaptured(captured)
	names := map[string]string{}
	for _, group := range groups {
		for _, id := range group.SessionIDs {
			names[id] = group.Identity.Canonical
		}
	}
	var result *storage.IntegrityResult
	if options.all {
		result, err = db.VerifyIntegrity()
	} else {
		ids := []string{}
		for _, group := range repository.Match(selected, groups) {
			ids = append(ids, group.SessionIDs...)
		}
		result, err = db.VerifyIntegrityForSessions(ids)
	}
	if err != nil {
		return err
	}
	report := verificationReport{IntegrityResult: result, Status: "verified", Scope: "repository", Repository: selected.Canonical, Storage: path}
	if options.all {
		report.Scope = "all"
	}
	if !result.Valid {
		report.Status = "failed"
	}
	if result.EventsChecked == 0 && result.SessionsChecked == 0 {
		report.Status = "no_records"
		result.Valid = false
	}
	if options.json {
		err = writeJSON(cmd.OutOrStdout(), report)
	} else {
		err = renderVerification(cmd.OutOrStdout(), report, names, options.details)
	}
	if err != nil {
		return err
	}
	if report.Status == "failed" {
		return fmt.Errorf("audit trail integrity check failed")
	}
	if report.Status == "no_records" {
		return fmt.Errorf("no audit records found for the selected scope")
	}
	return nil
}

var findingLabels = map[string]string{
	"legacy_event":          "Legacy event without complete coverage",
	"legacy_session":        "Legacy session without complete coverage",
	"broken_chain":          "Broken event chain",
	"event_hash_mismatch":   "Event hash mismatch",
	"session_hash_mismatch": "Session metadata hash mismatch",
	"unprotected_metadata":  "Metadata not covered by stored hash",
}

func renderVerification(w io.Writer, report verificationReport, repositories map[string]string, details bool) error {
	title := map[string]string{"verified": "VERIFIED", "failed": "FAILED", "no_records": "NO RECORDS"}[report.Status]
	fmt.Fprintf(w, "Audit trail verification %s\n\n", title)
	scope := report.Repository
	if report.Scope == "all" {
		scope = "All local repositories"
	}
	fmt.Fprintf(w, "Scope     %s\nChecked   %d events across %d sessions\nStorage   %s\n", scope, report.EventsChecked, report.SessionsChecked, report.Storage)
	if report.Status == "no_records" {
		_, err := fmt.Fprintln(w, "\nNo audit records found for this scope; nothing was verified.")
		return err
	}
	if report.Status == "verified" {
		_, err := fmt.Fprintln(w, "\nStored event chains and session metadata passed integrity verification.")
		return err
	}
	type summary struct {
		agent  string
		events map[int]bool
		kinds  map[string]bool
	}
	summaries := map[string]*summary{}
	for _, f := range report.Findings {
		s := summaries[f.SessionID]
		if s == nil {
			s = &summary{agent: f.Agent, events: map[int]bool{}, kinds: map[string]bool{}}
			summaries[f.SessionID] = s
		}
		// Findings with a sequence belong to an event; session checks omit it.
		if f.Kind != "legacy_session" && f.Kind != "session_hash_mismatch" {
			s.events[f.Sequence] = true
		}
		s.kinds[f.Kind] = true
	}
	ids := make([]string, 0, len(summaries))
	failedEvents := 0
	for id, s := range summaries {
		ids = append(ids, id)
		failedEvents += len(s.events)
	}
	sort.Strings(ids)
	fmt.Fprintf(w, "Affected  %s across %s\n\n", counted(failedEvents, "event"), counted(len(ids), "session"))
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "REPOSITORY\tAGENT\tSESSION\tFAILED EVENTS\tFINDING")
	limit := len(ids)
	if !details && limit > 10 {
		limit = 10
	}
	for _, id := range ids[:limit] {
		s := summaries[id]
		kinds := make([]string, 0, len(s.kinds))
		for kind := range s.kinds {
			kinds = append(kinds, findingLabels[kind])
		}
		sort.Strings(kinds)
		repo := repositories[id]
		if repo == "" {
			repo = "unknown"
		}
		session := id
		if !details {
			repo = compactRepository(repo, repositories)
			if len(id) > 12 {
				prefix := id[:12]
				unique := true
				for _, other := range ids {
					if other != id && strings.HasPrefix(other, prefix) {
						unique = false
						break
					}
				}
				if unique {
					session = prefix
				}
			}
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\n", terminalCell(repo), terminalCell(s.agent), terminalCell(session), len(s.events), strings.Join(kinds, "; "))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if limit < len(ids) {
		fmt.Fprintf(w, "\nShowing %d of %d affected sessions. Use --details for all findings.\n", limit, len(ids))
	}
	if details {
		fmt.Fprintln(w, "\nIndividual findings:")
		for _, f := range report.Findings {
			location := f.SessionID
			if f.Kind != "legacy_session" && f.Kind != "session_hash_mismatch" {
				location += fmt.Sprintf(":%d", f.Sequence)
			}
			fmt.Fprintf(w, "  %s: %s\n", terminalCell(location), findingLabels[f.Kind])
		}
	}
	_, err := fmt.Fprintln(w, "\nSome stored records failed integrity checks or lack complete integrity coverage.\nThe cause has not been determined; this alone does not establish deliberate tampering.\nRepeat this command with --details to inspect findings, or --json to export them.")
	return err
}

// Stored metadata must not inject terminal control sequences or table columns.
func terminalCell(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, value)
}

func counted(n int, noun string) string {
	if n != 1 {
		noun += "s"
	}
	return fmt.Sprintf("%d %s", n, noun)
}

// Use a short repository name only when it identifies one captured repository.
func compactRepository(canonical string, repositories map[string]string) string {
	parts := strings.Split(canonical, "/")
	name := parts[len(parts)-1]
	for _, other := range repositories {
		if other != canonical && (other == name || strings.HasSuffix(other, "/"+name)) {
			return canonical
		}
	}
	return name
}
