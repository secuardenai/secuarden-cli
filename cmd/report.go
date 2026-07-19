package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var (
	reportSince         string
	reportMD            bool
	reportJSON          bool
	reportRepo          string
	reportAllRepos      bool
	reportAbsolutePaths bool
	reportLimit         int
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate an aggregated local accountability report",
	Long: `Aggregate authoritative local capture data over a time window (default: 24h).

By default, the report is scoped to the Git repository containing the current
directory. Use --repo to select another repository or --all-repos to preserve
cross-repository reporting. Path display never changes the original JSON paths.`,
	Args: cobra.NoArgs,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportSince, "since", "24h", "report window (for example 24h or 7d)")
	reportCmd.Flags().BoolVar(&reportMD, "md", false, "emit Markdown suitable for tickets and audit records")
	reportCmd.Flags().BoolVar(&reportJSON, "json", false, "emit stable JSON")
	reportCmd.Flags().StringVar(&reportRepo, "repo", "", "repository path, remote URL, or owner/repository identity")
	reportCmd.Flags().BoolVar(&reportAllRepos, "all-repos", false, "include all repositories, grouped by repository")
	reportCmd.Flags().BoolVar(&reportAbsolutePaths, "absolute-paths", false, "display original absolute paths")
	reportCmd.Flags().IntVar(&reportLimit, "limit", 10, "maximum entries shown per terminal list")
	reportCmd.MarkFlagsMutuallyExclusive("md", "json")
	reportCmd.MarkFlagsMutuallyExclusive("repo", "all-repos")
}

func runReport(cmd *cobra.Command, args []string) error {
	now := time.Now()
	duration, err := parseTimeWindow(reportSince)
	if err != nil {
		return err
	}
	if err := validateReportOptions(reportRepo, reportAllRepos, reportLimit); err != nil {
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
	refs, err := db.ListSessionRepositories()
	if err != nil {
		return err
	}
	captured := make([]repository.CapturedRef, 0, len(refs))
	for _, ref := range refs {
		captured = append(captured, repository.CapturedRef{
			SessionID: ref.SessionID, GitRepoURL: ref.GitRepoURL,
			WorkingDirectory: ref.WorkingDirectory,
		})
	}
	groups := repository.GroupCaptured(captured)
	selected, selectedGroups, err := selectReportRepositories(reportRepo, reportAllRepos, groups)
	if err != nil {
		return err
	}
	report, err := collectScopedReport(db, now.Add(-duration), now, selected, selectedGroups, reportAllRepos, reportAbsolutePaths)
	if err != nil {
		return err
	}
	if reportJSON {
		return writeJSON(cmd.OutOrStdout(), report)
	}
	return renderReportWithLimit(cmd.OutOrStdout(), report, reportMD, reportLimit)
}

func validateReportOptions(repoValue string, all bool, limit int) error {
	if repoValue != "" && all {
		return fmt.Errorf("--repo and --all-repos are mutually exclusive")
	}
	if limit <= 0 {
		return fmt.Errorf("--limit must be greater than zero")
	}
	return nil
}

func selectReportRepositories(value string, all bool, groups []repository.Group) (repository.Identity, []repository.Group, error) {
	if all {
		return repository.Identity{Canonical: "all", Name: "All repositories"}, groups, nil
	}
	var selected repository.Identity
	var err error
	if value == "" {
		selected, err = repository.ResolveCurrent("")
		if err != nil {
			return repository.Identity{}, nil, fmt.Errorf("cannot determine report repository: %w; run inside a Git repository, or use --repo or --all-repos", err)
		}
	} else if _, statErr := os.Stat(value); statErr == nil {
		selected, err = repository.ResolvePath(value)
	} else {
		selected, err = repository.ResolveIdentity(value, groups)
	}
	if err != nil {
		return repository.Identity{}, nil, err
	}
	matched := repository.Match(selected, groups)
	for _, group := range matched {
		for _, root := range group.Identity.Roots {
			if !containsString(selected.Roots, root) {
				selected.Roots = append(selected.Roots, root)
			}
		}
	}
	return selected, matched, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func collectScopedReport(db *storage.DB, since, until time.Time, selected repository.Identity, groups []repository.Group, all, absolute bool) (*storage.AccountabilityReport, error) {
	home, _ := os.UserHomeDir()
	if !all {
		sessionIDs := groupSessionIDs(groups)
		report, err := db.GetAccountabilityReportForSessions(since, until, sessionIDs, true)
		if err != nil {
			return nil, err
		}
		report.Repository = selected.Canonical
		decorateReportPaths(report, selected, home, absolute, false)
		return report, nil
	}

	allSessionIDs := groupSessionIDs(groups)
	report, err := db.GetAccountabilityReportForSessions(since, until, allSessionIDs, true)
	if err != nil {
		return nil, err
	}
	report.Repository = "all"
	report.RepositoryGroups = make([]storage.RepositoryReport, 0)
	report.FileEntries = make([]storage.ReportPath, 0)
	for _, group := range groups {
		groupReport, err := db.GetAccountabilityReportForSessions(since, until, group.SessionIDs, true)
		if err != nil {
			return nil, err
		}
		if groupReport.Totals.Actions == 0 {
			continue
		}
		groupReport.Repository = group.Identity.Canonical
		decorateReportPaths(groupReport, group.Identity, home, absolute, true)
		report.FileEntries = append(report.FileEntries, groupReport.FileEntries...)
		report.RepositoryGroups = append(report.RepositoryGroups, storage.RepositoryReport{
			Repository: group.Identity.Canonical, Name: group.Identity.Name,
			Totals: groupReport.Totals, Agents: groupReport.Agents,
			FilesRead: groupReport.FilesRead, FilesChanged: groupReport.FilesChanged,
			FileEntries: groupReport.FileEntries, Attention: groupReport.Attention,
			SensitiveAccesses: groupReport.SensitiveAccesses,
			CommandExecutions: groupReport.CommandExecutions, CommandFailures: groupReport.CommandFailures,
			MCPActivity: groupReport.MCPActivity, Developers: groupReport.Developers, Branches: groupReport.Branches,
			RepositoryFilesRead: groupReport.RepositoryFilesRead, ExternalFilesRead: groupReport.ExternalFilesRead,
			RepositoryFilesChanged: groupReport.RepositoryFilesChanged, ExternalFilesChanged: groupReport.ExternalFilesChanged,
		})
	}
	classifyReportPaths(report)
	return report, nil
}

func groupSessionIDs(groups []repository.Group) []string {
	result := make([]string, 0)
	for _, group := range groups {
		result = append(result, group.SessionIDs...)
	}
	return result
}

func decorateReportPaths(report *storage.AccountabilityReport, repo repository.Identity, home string, absolute, prefix bool) {
	report.FileEntries = make([]storage.ReportPath, 0, len(report.FilesRead)+len(report.FilesChanged))
	if len(report.PathEvidence) > 0 {
		for _, evidence := range report.PathEvidence {
			pathForDisplay := evidence.FilePath
			if !filepath.IsAbs(pathForDisplay) && filepath.IsAbs(evidence.WorkingDirectory) {
				pathForDisplay = filepath.Join(evidence.WorkingDirectory, pathForDisplay)
			}
			display := repository.FormatPath(pathForDisplay, repo, home, absolute, prefix)
			report.FileEntries = append(report.FileEntries, storage.ReportPath{
				FilePath: evidence.FilePath, DisplayPath: display.Display,
				Repository: display.Repository, External: display.External, Kind: evidence.Kind,
				WorkingDirectory: evidence.WorkingDirectory, ResolvedPath: filepath.Clean(pathForDisplay),
			})
		}
		classifyReportPaths(report)
		return
	}
	for _, kindAndPaths := range []struct {
		kind  string
		paths []string
	}{{"read", report.FilesRead}, {"changed", report.FilesChanged}} {
		for _, path := range kindAndPaths.paths {
			display := repository.FormatPath(path, repo, home, absolute, prefix)
			report.FileEntries = append(report.FileEntries, storage.ReportPath{
				FilePath: display.Original, DisplayPath: display.Display,
				Repository: display.Repository, External: display.External, Kind: kindAndPaths.kind,
				ResolvedPath: filepath.Clean(path),
			})
		}
	}
	classifyReportPaths(report)
}

func classifyReportPaths(report *storage.AccountabilityReport) {
	type classified struct {
		entry storage.ReportPath
		key   string
	}
	unique := map[string]classified{}
	for _, entry := range report.FileEntries {
		resolved := entry.ResolvedPath
		if resolved == "" {
			resolved = filepath.Clean(entry.FilePath)
		}
		key := entry.Repository + "\x00" + entry.Kind + "\x00" + fmt.Sprintf("%t", entry.External) + "\x00" + resolved
		if _, exists := unique[key]; !exists {
			unique[key] = classified{entry: entry, key: key}
		}
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	report.FileEntries = make([]storage.ReportPath, 0, len(keys))
	report.RepositoryFilesRead = make([]string, 0)
	report.ExternalFilesRead = make([]string, 0)
	report.RepositoryFilesChanged = make([]string, 0)
	report.ExternalFilesChanged = make([]string, 0)
	for _, key := range keys {
		entry := unique[key].entry
		report.FileEntries = append(report.FileEntries, entry)
		switch {
		case entry.Kind == "read" && entry.External:
			report.ExternalFilesRead = append(report.ExternalFilesRead, entry.FilePath)
		case entry.Kind == "read":
			report.RepositoryFilesRead = append(report.RepositoryFilesRead, entry.FilePath)
		case entry.Kind == "changed" && entry.External:
			report.ExternalFilesChanged = append(report.ExternalFilesChanged, entry.FilePath)
		case entry.Kind == "changed":
			report.RepositoryFilesChanged = append(report.RepositoryFilesChanged, entry.FilePath)
		}
	}
	report.Totals.RepositoryFilesRead = len(report.RepositoryFilesRead)
	report.Totals.ExternalFilesRead = len(report.ExternalFilesRead)
	report.Totals.RepositoryFilesChanged = len(report.RepositoryFilesChanged)
	report.Totals.ExternalFilesChanged = len(report.ExternalFilesChanged)
}

func parseTimeWindow(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseUint(strings.TrimSuffix(value, "d"), 10, 31)
		if err != nil || days == 0 {
			return 0, fmt.Errorf("invalid --since %q: use a positive duration such as 24h or 7d", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid --since %q: use a positive duration such as 24h or 7d", value)
	}
	return duration, nil
}

func renderReport(w io.Writer, r *storage.AccountabilityReport, markdown bool) error {
	return renderReportWithLimit(w, r, markdown, 10)
}

func renderReportWithLimit(w io.Writer, r *storage.AccountabilityReport, markdown bool, limit int) error {
	return renderReportWithOptions(w, r, markdown, limit, time.Local)
}

func renderReportWithOptions(w io.Writer, r *storage.AccountabilityReport, markdown bool, limit int, location *time.Location) error {
	if location == nil {
		location = time.Local
	}
	heading := func(level int, title string) {
		if markdown {
			fmt.Fprintf(w, "%s %s\n\n", strings.Repeat("#", level), title)
		} else if level == 1 {
			fmt.Fprintf(w, "%s\n\n", title)
		} else {
			fmt.Fprintf(w, "\n%s\n", title)
		}
	}
	bullet := func(text string) {
		if markdown {
			fmt.Fprintf(w, "- %s\n", text)
		} else {
			fmt.Fprintf(w, "  %s\n", text)
		}
	}
	sectionEnd := func() {
		if markdown {
			fmt.Fprintln(w)
		}
	}

	if markdown {
		heading(1, "Secuarden accountability report")
	} else {
		fmt.Fprintln(w, "Secuarden accountability report")
	}
	repositoryLabel := displayRepositoryIdentity(r.Repository)
	if repositoryLabel != "" {
		fmt.Fprintf(w, "Repository: %s\n", repositoryLabel)
	}
	fmt.Fprintf(w, "Period: %s\n", friendlyReportPeriod(r.Since, r.Until, location))
	if markdown {
		fmt.Fprintln(w)
	}
	if r.Totals.Actions == 0 {
		fmt.Fprintln(w, "\nNo captured activity matched the selected repository and period.")
		return nil
	}
	renderReportSummary(heading, bullet, sectionEnd, r, 2)

	if len(r.RepositoryGroups) > 0 {
		for _, group := range r.RepositoryGroups {
			heading(2, "Repository: "+displayRepositoryIdentity(group.Repository))
			groupReport := reportFromGroup(group, r.Since, r.Until)
			renderReportSummary(heading, bullet, sectionEnd, groupReport, 3)
			renderReportDetails(heading, bullet, sectionEnd, groupReport, markdown, limit, 3, location)
		}
		return nil
	}
	renderReportDetails(heading, bullet, sectionEnd, r, markdown, limit, 2, location)
	return nil
}

func renderReportSummary(heading func(int, string), bullet func(string), end func(), r *storage.AccountabilityReport, level int) {
	heading(level, "Summary")
	bullet(fmt.Sprintf("%s · %s", countNoun(r.Totals.Sessions, "session"), countNoun(r.Totals.Actions, "action")))
	bullet(fmt.Sprintf("%s changed · %s changed",
		countNoun(r.Totals.RepositoryFilesChanged, "repository file"),
		countNoun(r.Totals.ExternalFilesChanged, "external file")))
	succeeded := r.CommandExecutions - r.CommandFailures
	if succeeded < 0 {
		succeeded = 0
	}
	bullet(fmt.Sprintf("%s succeeded · %d failed", countNoun(succeeded, "command"), r.CommandFailures))
	if r.Totals.SensitiveAccesses == 0 {
		bullet("No sensitive-path access")
	} else {
		bullet(countNoun(r.Totals.SensitiveAccesses, "sensitive-path access"))
	}
	end()
}

func renderReportDetails(heading func(int, string), bullet func(string), sectionEnd func(), r *storage.AccountabilityReport, markdown bool, limit, level int, location *time.Location) {
	if len(r.Agents) > 0 {
		heading(level, "Agent activity")
		for _, agent := range r.Agents {
			bullet(fmt.Sprintf("%s · %s · %s", displayAgent(agent.Name), countNoun(agent.Sessions, "session"), countNoun(agent.Count, "action")))
		}
		sectionEnd()
	}
	renderReportPaths(heading, bullet, sectionEnd, level, "Files changed", reportPaths(r, "changed", false), "", markdown, limit)
	renderReportPaths(heading, bullet, sectionEnd, level, "Files read", reportPaths(r, "read", false), "", markdown, limit)
	renderExternalActivity(heading, bullet, sectionEnd, r, markdown, limit, level)

	if len(r.SensitiveAccesses) > 0 {
		heading(level, "Sensitive-path access")
		for _, event := range r.SensitiveAccesses {
			bullet(fmt.Sprintf("[SENSITIVE] %s · %s · session %s", humanReportTimestamp(event.Timestamp, location), displayEventSummary(r, event), event.SessionID))
		}
		sectionEnd()
	}

	failures := nonSensitiveFailures(r.Attention)
	if len(failures) > 0 {
		heading(level, "Failed, blocked, and rejected actions")
		for _, finding := range failures {
			bullet(fmt.Sprintf("%s · %s%s", findingLabel(finding.Kind), displayFindingSummary(r, finding), findingSuffix(finding)))
		}
		sectionEnd()
	}
	if len(r.MCPActivity) > 0 {
		renderNamedSection(heading, bullet, sectionEnd, level, "MCP activity", r.MCPActivity, "call")
	}
	if len(r.Developers) > 0 {
		renderNamedSection(heading, bullet, sectionEnd, level, "Developer footprint", r.Developers, "action")
	}
	if len(r.Branches) > 0 {
		renderNamedSection(heading, bullet, sectionEnd, level, "Branch footprint", r.Branches, "action")
	}
}

func humanReportTimestamp(value string, location *time.Location) string {
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return timestamp.In(location).Format("02 Jan 15:04 MST")
}

func friendlyReportPeriod(sinceValue, untilValue string, location *time.Location) string {
	since, sinceErr := time.Parse(time.RFC3339Nano, sinceValue)
	until, untilErr := time.Parse(time.RFC3339Nano, untilValue)
	if sinceErr != nil || untilErr != nil {
		return sinceValue + " to " + untilValue
	}
	duration := until.Sub(since)
	label := duration.String()
	hours := int(duration.Hours())
	if duration == 24*time.Hour {
		label = "24 hours"
	} else if duration%(24*time.Hour) == 0 && duration >= 48*time.Hour {
		label = countNoun(int(duration/(24*time.Hour)), "day")
	} else if duration%time.Hour == 0 {
		label = countNoun(hours, "hour")
	}
	localSince, localUntil := since.In(location), until.In(location)
	zone := localUntil.Format("MST")
	return fmt.Sprintf("Last %s · %s – %s %s", label, localSince.Format("02 Jan 15:04"), localUntil.Format("02 Jan 15:04"), zone)
}

func displayRepositoryIdentity(identity string) string {
	if identity == "all" {
		return "All repositories"
	}
	if strings.HasPrefix(identity, "local:") || strings.HasPrefix(identity, "unverified:") || identity == "unknown" {
		return identity
	}
	parts := strings.Split(identity, "/")
	if len(parts) >= 3 && strings.Contains(parts[0], ".") {
		return strings.Join(parts[1:], "/")
	}
	return identity
}

func reportFromGroup(group storage.RepositoryReport, since, until string) *storage.AccountabilityReport {
	return &storage.AccountabilityReport{
		Since: since, Until: until, Repository: group.Repository, Totals: group.Totals,
		Agents: group.Agents, FilesRead: group.FilesRead, FilesChanged: group.FilesChanged,
		FileEntries: group.FileEntries, Attention: group.Attention, SensitiveAccesses: group.SensitiveAccesses,
		CommandExecutions: group.CommandExecutions, CommandFailures: group.CommandFailures,
		MCPActivity: group.MCPActivity, Developers: group.Developers, Branches: group.Branches,
		RepositoryFilesRead: group.RepositoryFilesRead, ExternalFilesRead: group.ExternalFilesRead,
		RepositoryFilesChanged: group.RepositoryFilesChanged, ExternalFilesChanged: group.ExternalFilesChanged,
	}
}

func reportPaths(r *storage.AccountabilityReport, kind string, external bool) []string {
	result := make([]string, 0)
	for _, entry := range r.FileEntries {
		if entry.Kind == kind && entry.External == external {
			result = append(result, entry.DisplayPath)
		}
	}
	if len(r.FileEntries) == 0 && !external {
		if kind == "read" {
			return r.FilesRead
		}
		return r.FilesChanged
	}
	return result
}

func displayEventSummary(r *storage.AccountabilityReport, event storage.StoredEvent) string {
	if event.FilePath != "" {
		for _, entry := range r.FileEntries {
			if entry.FilePath == event.FilePath && (entry.WorkingDirectory == "" || entry.WorkingDirectory == event.WorkingDirectory) {
				return entry.DisplayPath
			}
		}
	}
	return eventSummary(event)
}

func displayFindingSummary(r *storage.AccountabilityReport, finding storage.AttentionFinding) string {
	for _, entry := range r.FileEntries {
		if entry.FilePath == finding.Summary {
			return entry.DisplayPath
		}
	}
	return finding.Summary
}

func renderNamedSection(heading func(int, string), bullet func(string), end func(), level int, title string, values []storage.NamedCount, noun string) {
	heading(level, title)
	for _, value := range values {
		bullet(fmt.Sprintf("%s · %s", value.Name, countNoun(value.Count, noun)))
	}
	end()
}

func renderReportPaths(heading func(int, string), bullet func(string), end func(), level int, title string, values []string, empty string, markdown bool, limit int) {
	if len(values) == 0 && empty == "" {
		return
	}
	heading(level, title)
	if len(values) == 0 {
		bullet(empty)
		end()
		return
	}
	visible := values
	if !markdown && limit > 0 && len(visible) > limit {
		visible = visible[:limit]
	}
	for _, value := range visible {
		bullet(value)
	}
	if len(visible) < len(values) {
		remaining := len(values) - len(visible)
		if remaining == 1 {
			bullet("… 1 more")
		} else {
			bullet(fmt.Sprintf("… %d more", remaining))
		}
	}
	end()
}

func renderExternalActivity(heading func(int, string), bullet func(string), end func(), r *storage.AccountabilityReport, markdown bool, limit, level int) {
	reads := reportPaths(r, "read", true)
	changes := reportPaths(r, "changed", true)
	if len(reads) == 0 && len(changes) == 0 {
		return
	}
	type activity struct {
		action string
		path   string
	}
	items := make([]activity, 0, len(reads)+len(changes))
	for _, path := range reads {
		items = append(items, activity{"Read", path})
	}
	for _, path := range changes {
		items = append(items, activity{"Changed", path})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].path == items[j].path {
			return items[i].action < items[j].action
		}
		return items[i].path < items[j].path
	})
	heading(level, "External activity")
	visible := items
	if !markdown && limit > 0 && len(visible) > limit {
		visible = visible[:limit]
	}
	for _, item := range visible {
		bullet(fmt.Sprintf("%-7s  %s", item.action, item.path))
	}
	if len(visible) < len(items) {
		remaining := len(items) - len(visible)
		if remaining == 1 {
			bullet("… 1 more")
		} else {
			bullet(fmt.Sprintf("… %d more", remaining))
		}
	}
	end()
}
