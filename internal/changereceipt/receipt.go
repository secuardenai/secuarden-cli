package changereceipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

const EvidenceVersion = "secuarden.receipt-evidence/v1"
const MaxEnvelope = 10 * 1024 * 1024

type GitRevision struct {
	ObjectFormat string `json:"object_format"`
	BaseCommit   string `json:"base_commit"`
	BaseTree     string `json:"base_tree"`
	HeadCommit   string `json:"head_commit"`
	HeadTree     string `json:"head_tree"`
}
type Payload struct {
	Schema         string      `json:"schema"`
	ReceiptID      string      `json:"receipt_id"`
	KeyID          string      `json:"key_id"`
	TenantID       string      `json:"tenant_id"`
	IssuedAt       string      `json:"issued_at"`
	Git            GitRevision `json:"git"`
	Repository     Repository  `json:"repository"`
	ChangeSchema   string      `json:"change_schema"`
	ChangeDigest   string      `json:"change_digest"`
	EvidenceSchema string      `json:"evidence_schema"`
	EvidenceDigest string      `json:"evidence_digest"`
}
type Evidence struct {
	Schema       string                               `json:"schema"`
	SnapshotAt   string                               `json:"snapshot_at"`
	Change       *changeledger.Change                 `json:"change"`
	Scopes       []changeledger.ObservationScope      `json:"scopes"`
	Observations []observationcapture.Observation     `json:"observations"`
	Checkpoints  []changeledger.ObservationCheckpoint `json:"checkpoints"`
	Links        []changeledger.ObservationLink       `json:"inferred_links"`
	Coverage     *changeledger.Coverage               `json:"coverage"`
	Sources      map[string]string                    `json:"sources"`
}
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
	Evidence  json.RawMessage `json:"evidence"`
}
type Artifact struct {
	Envelope     Envelope     `json:"envelope"`
	PublicKey    string       `json:"public_key"`
	Registration Registration `json:"registration"`
}

// Canonical rejects unsafe integers and malformed JSON before using RFC 8785 JCS.
func Canonical(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := validateJSON(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return jsoncanonicalizer.Transform(raw)
}
func validateJSON(d *json.Decoder, depth int) error {
	if depth > 100 {
		return fmt.Errorf("JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return fmt.Errorf("duplicate or invalid JSON key")
				}
				seen[k] = true
				if err := validateJSON(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := validateJSON(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	case json.Number:
		if _, err := strconv.ParseFloat(string(v), 64); err != nil {
			return fmt.Errorf("non-finite or invalid JSON number")
		}
		r, ok := new(big.Rat).SetString(string(v))
		if !ok {
			return fmt.Errorf("invalid JSON number")
		}
		if r.IsInt() && new(big.Int).Abs(r.Num()).Cmp(big.NewInt(9007199254740991)) > 0 {
			return fmt.Errorf("unsafe JSON integer")
		}
	}
	return nil
}
func canonicalObject(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonical(raw)
}
func digest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
func NewArtifact(provider SigningProvider, registration *Registration, e Evidence) (*Artifact, error) {
	if e.Coverage == nil {
		return nil, fmt.Errorf("coverage is required")
	}
	if err := changeledger.VerifyChange(e.Change); err != nil {
		return nil, err
	}
	if registration == nil || registration.KeyID != KeyID(provider.PublicKey()) {
		return nil, fmt.Errorf("registration key mismatch")
	}
	e.Schema = EvidenceVersion
	if e.SnapshotAt == "" {
		e.SnapshotAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	sort.Slice(e.Coverage.Reasons, func(i, j int) bool {
		a, _ := canonicalObject(e.Coverage.Reasons[i])
		b, _ := canonicalObject(e.Coverage.Reasons[j])
		return bytes.Compare(a, b) < 0
	})
	evidence, err := canonicalObject(e)
	if err != nil {
		return nil, err
	}
	c := e.Change
	format := "sha1"
	if len(c.HeadCommit) == 64 {
		format = "sha256"
	}
	p := Payload{ProtocolVersion, uuid.NewString(), registration.KeyID, registration.TenantID, time.Now().UTC().Format(time.RFC3339Nano), GitRevision{format, c.BaseCommit, c.BaseTree, c.HeadCommit, c.HeadTree}, registration.Repository, changeledger.ContractVersion, c.Digest, EvidenceVersion, digest(evidence)}
	payload, err := canonicalObject(p)
	if err != nil {
		return nil, err
	}
	sig, err := provider.Sign(append([]byte(ProtocolVersion+"\n"), payload...))
	if err != nil {
		return nil, err
	}
	a := &Artifact{Envelope{payload, base64.StdEncoding.EncodeToString(sig), evidence}, base64.StdEncoding.EncodeToString(provider.PublicKey()), *registration}
	return a, a.Verify()
}
func (a *Artifact) Verify() error {
	pbytes, err := Canonical(a.Envelope.Payload)
	if err != nil {
		return err
	}
	ebytes, err := Canonical(a.Envelope.Evidence)
	if err != nil {
		return err
	}
	if !bytes.Equal(pbytes, a.Envelope.Payload) || !bytes.Equal(ebytes, a.Envelope.Evidence) {
		return fmt.Errorf("noncanonical stored artifact")
	}
	var p Payload
	var e Evidence
	pd := json.NewDecoder(bytes.NewReader(pbytes))
	pd.DisallowUnknownFields()
	if err = pd.Decode(&p); err != nil {
		return err
	}
	ed := json.NewDecoder(bytes.NewReader(ebytes))
	ed.DisallowUnknownFields()
	if err = ed.Decode(&e); err != nil {
		return err
	}
	if e.Coverage == nil || e.Coverage.ChangeDigest != p.ChangeDigest {
		return fmt.Errorf("invalid coverage binding")
	}
	for _, stamp := range []string{p.IssuedAt, e.SnapshotAt} {
		parsed, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || parsed.IsZero() || !strings.HasSuffix(stamp, "Z") {
			return fmt.Errorf("invalid client timestamp")
		}
	}
	if p.TenantID == "" || p.Repository.Provider != "github" || !repositoryID.MatchString(p.Repository.ID) || !repositoryName.MatchString(p.Repository.FullName) {
		return fmt.Errorf("invalid repository identity")
	}
	public, err := base64.StdEncoding.Strict().DecodeString(a.PublicKey)
	if err != nil || len(public) != 32 {
		return fmt.Errorf("invalid public key")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(a.Envelope.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(ProtocolVersion+"\n"), pbytes...), sig) {
		return fmt.Errorf("invalid receipt signature")
	}
	id, err := uuid.Parse(p.ReceiptID)
	if err != nil || id.Version() != 4 {
		return fmt.Errorf("invalid receipt ID")
	}
	if p.Schema != ProtocolVersion || p.EvidenceSchema != EvidenceVersion || e.Schema != EvidenceVersion || p.ChangeSchema != changeledger.ContractVersion || p.KeyID != KeyID(public) || p.KeyID != a.Registration.KeyID || p.TenantID != a.Registration.TenantID || p.Repository != a.Registration.Repository || p.EvidenceDigest != digest(ebytes) {
		return fmt.Errorf("receipt schema or identity mismatch")
	}
	if err := changeledger.VerifyChange(e.Change); err != nil {
		return err
	}
	c := e.Change
	if c.Digest != p.ChangeDigest || p.Git.BaseCommit != c.BaseCommit || p.Git.HeadCommit != c.HeadCommit || p.Git.BaseTree != c.BaseTree || p.Git.HeadTree != c.HeadTree {
		return fmt.Errorf("revision mismatch")
	}
	size := 40
	if p.Git.ObjectFormat == "sha256" {
		size = 64
	} else if p.Git.ObjectFormat != "sha1" {
		return fmt.Errorf("invalid object format")
	}
	for _, oid := range []string{c.BaseCommit, c.HeadCommit, c.BaseTree, c.HeadTree} {
		if len(oid) != size || strings.Trim(oid, "0123456789abcdef") != "" {
			return fmt.Errorf("invalid Git object ID")
		}
	}
	raw, err := json.Marshal(a.Envelope)
	if err != nil {
		return err
	}
	if len(raw) > MaxEnvelope {
		return fmt.Errorf("receipt exceeds 10 MiB upload limit")
	}
	return nil
}
func (a *Artifact) Payload() Payload {
	var p Payload
	_ = json.Unmarshal(a.Envelope.Payload, &p)
	return p
}
