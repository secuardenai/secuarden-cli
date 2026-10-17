package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/changereceipt"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/spf13/cobra"
)

// HookExitError preserves a pre-existing hook's rejection status.
type HookExitError struct {
	Code int
	Err  error
}

func (e *HookExitError) Error() string { return e.Err.Error() }

func addReceiptWorkflow(receipt *cobra.Command) {
	create := &cobra.Command{Use: "create", Short: "Create, save and upload an exact signed change receipt", Args: cobra.NoArgs, RunE: runReceiptCreate}
	create.Flags().String("repo", ".", "local repository")
	create.Flags().String("head", "HEAD", "committed head")
	create.Flags().String("base", "", "exact base commit")
	create.Flags().String("base-ref", "", "target ref for merge-base selection")
	create.MarkFlagsMutuallyExclusive("base", "base-ref")
	create.Flags().StringSlice("session", nil, "explicit session IDs (repeat or comma-separate)")
	create.Flags().String("since", "", "scope start, RFC3339")
	create.Flags().String("until", "", "scope end, RFC3339")
	create.Flags().Bool("json", false, "full structured output")
	create.Flags().Bool("full", false, "full evidence output")
	receipt.AddCommand(create)
	for _, name := range []string{"show", "upload", "export"} {
		name := name
		c := &cobra.Command{Use: name + " RECEIPT_ID", Short: map[string]string{"show": "Inspect a verified local signed receipt", "upload": "Retry delivery of a saved signed receipt", "export": "Export a verified receipt envelope"}[name], Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openLedger()
			if err != nil {
				return err
			}
			defer store.Close()
			record, err := store.SignedReceipt(args[0])
			if err != nil {
				return err
			}
			var a changereceipt.Artifact
			if err = json.Unmarshal(record.Artifact, &a); err != nil {
				return err
			}
			if err = a.Verify(); err != nil {
				return err
			}
			switch name {
			case "upload":
				cfg, err := config.LoadForRepository(record.Root)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
				defer cancel()
				if err = uploadReceipt(ctx, store, cfg, &a); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Receipt uploaded:", args[0])
				return nil
			case "export":
				out, _ := cmd.Flags().GetString("output")
				raw, err := json.Marshal(a.Envelope)
				if err != nil {
					return err
				}
				raw, err = changereceipt.Canonical(raw)
				if err != nil {
					return err
				}
				f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return err
				}
				_, err = f.Write(raw)
				if err == nil {
					err = f.Sync()
				}
				closeErr := f.Close()
				if err == nil {
					err = closeErr
				}
				return err
			default:
				j, _ := cmd.Flags().GetBool("json")
				full, _ := cmd.Flags().GetBool("full")
				if j || full {
					return writeJSON(cmd.OutOrStdout(), record)
				}
				return renderReceipt(cmd.OutOrStdout(), &a, record.UploadState, record.UploadError, record.Acknowledgement)
			}
		}}
		c.Flags().Bool("json", false, "full structured output")
		c.Flags().Bool("full", false, "full evidence output")
		if name == "export" {
			c.Flags().String("output", "", "new output file")
			_ = c.MarkFlagRequired("output")
		}
		receipt.AddCommand(c)
	}
	hook := &cobra.Command{Use: "pre-push REMOTE URL", Hidden: true, Args: cobra.ExactArgs(2), RunE: runReceiptPrePush}
	hook.Flags().String("repo", ".", "repository")
	hook.Flags().String("original", "", "preserved hook")
	receipt.AddCommand(hook)
}
func createReceipt(ctx context.Context, store *changeledger.Store, path, head, base, baseRef, name string, scopes []changeledger.ObservationScope, logs io.Writer) (*changereceipt.Artifact, error) {
	identity, err := repository.ResolveCurrent(path)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadForRepository(identity.Root)
	if err != nil {
		return nil, err
	}
	if name == "" {
		remote, err := changereceipt.Git(identity.Root, "remote", "get-url", "origin")
		if err != nil {
			return nil, err
		}
		name, err = changereceipt.GitHubName(remote)
		if err != nil {
			return nil, err
		}
	}
	c, err := changeledger.Build(changeledger.BuildOptions{Repository: identity.Root, Head: head, Base: base, BaseRef: baseRef})
	if err != nil {
		return nil, err
	}
	if err = changeledger.VerifyChange(c); err != nil {
		return nil, err
	}
	if !strings.EqualFold(c.Repository, "github.com/"+name) {
		return nil, fmt.Errorf("push remote and ledger repository identity differ; select a matching origin")
	}
	fmt.Fprintf(logs, "Receipt revision: base %s, head %s (target ref %s; uncommitted work excluded).\n", c.BaseCommit, c.HeadCommit, baseRef)
	if _, err = store.Put(c); err != nil {
		return nil, err
	}
	for _, scope := range scopes {
		if _, err = store.Correlate(c.Digest, scope); err != nil {
			return nil, err
		}
	}
	coverage, obs, cps, err := store.ReceiptSnapshot(c.Digest)
	if err != nil {
		return nil, err
	}
	dir, err := observationcapture.DefaultDir()
	if err != nil {
		return nil, err
	}
	coverage.InspectInbox(dir)
	evidence := changereceipt.Evidence{Change: c, Scopes: coverage.Scopes, Observations: obs, Checkpoints: cps, Links: coverage.Links, Coverage: coverage, Sources: map[string]string{"cli_version": Version, "normalizer_version": observationcapture.Version, "attribution_version": observationcapture.Version}}
	provider, reg, err := changereceipt.PrepareSigningKey(ctx, cfg, name, logs, nil)
	if err != nil {
		return nil, err
	}
	defer provider.Close()
	a, err := changereceipt.NewArtifact(provider, reg, evidence)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if err = store.SaveSignedReceipt(a.Payload().ReceiptID, identity.Root, raw); err != nil {
		return nil, err
	}
	return a, nil
}
func uploadReceipt(ctx context.Context, store *changeledger.Store, cfg *config.Config, a *changereceipt.Artifact) error {
	ack, err := changereceipt.Upload(ctx, cfg, a, nil)
	state, detail := "uploaded", ""
	if err != nil {
		state, detail = "pending", err.Error()
		var permanent *changereceipt.TerminalUploadError
		if errors.As(err, &permanent) {
			state = "failed"
		}
	}
	if saveErr := store.ReceiptUploadOutcome(a.Payload().ReceiptID, state, detail, ack); saveErr != nil {
		return fmt.Errorf("persist upload outcome: %w", saveErr)
	}
	return err
}
func runReceiptCreate(cmd *cobra.Command, _ []string) error {
	path, _ := cmd.Flags().GetString("repo")
	identity, err := repository.ResolveCurrent(path)
	if err != nil {
		return err
	}
	cfg, err := config.LoadForRepository(identity.Root)
	if err != nil {
		return err
	}
	head, _ := cmd.Flags().GetString("head")
	base, _ := cmd.Flags().GetString("base")
	baseRef, _ := cmd.Flags().GetString("base-ref")
	if base == "" && baseRef == "" {
		baseRef = cfg.RepositoryIntegrations[identity.Root].Receipt.BaseRef
	}
	sessions, _ := cmd.Flags().GetStringSlice("session")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	scopes := []changeledger.ObservationScope{}
	if len(sessions) > 0 || since != "" || until != "" {
		start, e1 := time.Parse(time.RFC3339Nano, since)
		end, e2 := time.Parse(time.RFC3339Nano, until)
		if len(sessions) == 0 || e1 != nil || e2 != nil || !end.After(start) {
			return fmt.Errorf("session IDs and an ordered since/until window are required")
		}
		seen := map[string]bool{}
		for _, session := range sessions {
			if session == "" || seen[session] {
				return fmt.Errorf("session IDs must be nonempty and unique")
			}
			seen[session] = true
			scopes = append(scopes, changeledger.ObservationScope{SessionID: session, Since: start.UTC(), Until: end.UTC()})
		}
	}
	store, err := openLedger()
	if err != nil {
		return err
	}
	defer store.Close()
	a, err := createReceipt(cmd.Context(), store, path, head, base, baseRef, "", scopes, cmd.ErrOrStderr())
	if err != nil {
		_ = store.CaptureOutcome(identity.Root, "explicit", head, "", "creation failed", err.Error())
		return err
	}
	id := a.Payload().ReceiptID
	_ = store.CaptureOutcome(identity.Root, "explicit", a.Payload().Git.HeadCommit, id, "generated", "")
	ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
	defer cancel()
	uploadErr := uploadReceipt(ctx, store, cfg, a)
	record, err := store.SignedReceipt(id)
	if err != nil {
		return err
	}
	j, _ := cmd.Flags().GetBool("json")
	full, _ := cmd.Flags().GetBool("full")
	if j || full {
		err = writeJSON(cmd.OutOrStdout(), record)
	} else {
		err = renderReceipt(cmd.OutOrStdout(), a, record.UploadState, record.UploadError, record.Acknowledgement)
	}
	if err != nil {
		return err
	}
	return uploadErr
}
func renderReceipt(w io.Writer, a *changereceipt.Artifact, state, detail string, acknowledgement []byte) error {
	revisionMatch, receivedAt, inspection := "pending SaaS verification", "", ""
	if len(acknowledgement) > 0 {
		var ack changereceipt.UploadAcknowledgement
		if json.Unmarshal(acknowledgement, &ack) == nil {
			revisionMatch = ack.RevisionMatch + " (SaaS)"
			receivedAt = ack.ReceivedAt
			inspection = ack.InspectionURL
		}
	}
	p := a.Payload()
	width := sessionSummaryWidth()
	sessionSection(w, "SIGNED CHANGE RECEIPT", width, false)
	for _, r := range [][2]string{{"Receipt", p.ReceiptID}, {"Repository", p.Repository.FullName}, {"Base", p.Git.BaseCommit}, {"Head", p.Git.HeadCommit}, {"Change digest", p.ChangeDigest}, {"Evidence digest", p.EvidenceDigest}, {"Signing key", p.KeyID}, {"Client issued", p.IssuedAt}, {"Signature", "verified locally"}, {"Revision match", revisionMatch}, {"Server received", receivedAt}, {"Inspection", inspection}, {"Upload", state}, {"Upload detail", detail}} {
		if r[1] != "" {
			sessionField(w, r[0], r[1], width)
		}
	}
	var e changereceipt.Evidence
	_ = json.Unmarshal(a.Envelope.Evidence, &e)
	return renderCoverage(w, e.Coverage, false)
}
func runReceiptPrePush(cmd *cobra.Command, args []string) error {
	input, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return err
	}
	original, _ := cmd.Flags().GetString("original")
	if info, err := os.Stat(original); err == nil && info.Mode()&0111 != 0 {
		c := exec.Command(original, args...)
		c.Stdin = bytes.NewReader(input)
		c.Stdout = cmd.OutOrStdout()
		c.Stderr = cmd.ErrOrStderr()
		if err = c.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return &HookExitError{Code: exit.ExitCode(), Err: err}
			}
			return err
		}
	}
	// Secuarden failures below this point never reject the push.
	path, _ := cmd.Flags().GetString("repo")
	err = capturePush(cmd, path, args, input)
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Secuarden receipt capture:", err)
	}
	return nil
}
func capturePush(cmd *cobra.Command, path string, args []string, input []byte) error {
	identity, err := repository.ResolveCurrent(path)
	if err != nil {
		return err
	}
	store, err := openLedger()
	if err != nil {
		return err
	}
	defer store.Close()
	fail := func(err error) error {
		_ = store.CaptureOutcome(identity.Root, "push attempt", "", "", "creation failed", err.Error())
		return err
	}
	cfg, err := config.LoadForRepository(identity.Root)
	if err != nil {
		return fail(err)
	}
	options := cfg.RepositoryIntegrations[identity.Root].Receipt
	if options.Mode != "automatic" {
		return nil
	}
	updates, err := changereceipt.ParseUpdates(bytes.NewReader(input))
	if err != nil {
		return fail(err)
	}
	name, err := changereceipt.GitHubName(args[1])
	if err != nil {
		return fail(err)
	}
	artifacts := []*changereceipt.Artifact{}
	for _, u := range updates {
		if !strings.HasPrefix(u.Destination, "refs/heads/") || strings.Trim(u.Head, "0") == "" {
			_ = store.CaptureOutcome(identity.Root, u.Destination, u.Head, "", "skipped", "tag update or branch deletion")
			continue
		}
		baseRef := options.BaseRef
		if override := options.BranchBases[u.Destination]; override != "" {
			baseRef = override
		}
		var createErr error
		target, _ := changereceipt.Git(identity.Root, "rev-parse", "--symbolic-full-name", baseRef)
		targetBranch := strings.TrimPrefix(target, "refs/remotes/"+args[0]+"/")
		if options.BranchBases[u.Destination] == "" && (target == u.Destination || u.Destination == "refs/heads/"+targetBranch) {
			createErr = fmt.Errorf("pushing the target branch requires a destination-specific receipt base")
		}
		var a *changereceipt.Artifact
		if createErr == nil {
			a, createErr = createReceipt(cmd.Context(), store, path, u.Head, "", baseRef, name, nil, cmd.ErrOrStderr())
		}
		if createErr != nil {
			_ = store.CaptureOutcome(identity.Root, u.Destination, u.Head, "", "creation failed", createErr.Error())
			fmt.Fprintln(cmd.ErrOrStderr(), "Secuarden:", createErr)
			continue
		}
		_ = store.CaptureOutcome(identity.Root, u.Destination, u.Head, a.Payload().ReceiptID, "generated", "")
		artifacts = append(artifacts, a)
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
	defer cancel()
	for _, a := range artifacts {
		if err := uploadReceipt(ctx, store, cfg, a); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "Secuarden:", err)
		}
	}
	return nil
}
