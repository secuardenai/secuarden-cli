package changeledger

import (
	"encoding/json"
	"strings"
	"time"
)

const signedSchema = `CREATE TABLE IF NOT EXISTS signed_change_receipts_v1 (
 receipt_id TEXT PRIMARY KEY, root TEXT NOT NULL, artifact BLOB NOT NULL, stored_at TEXT NOT NULL,
 upload_state TEXT NOT NULL DEFAULT 'pending', upload_error TEXT NOT NULL DEFAULT '', acknowledgement BLOB);
 CREATE TABLE IF NOT EXISTS receipt_capture_outcomes_v1 (
 id INTEGER PRIMARY KEY, root TEXT NOT NULL, destination TEXT NOT NULL, head TEXT NOT NULL,
 receipt_id TEXT NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL, observed_at TEXT NOT NULL);`

func (s *Store) SaveSignedReceipt(id, root string, artifact []byte) error {
	_, err := s.db.Exec(`INSERT INTO signed_change_receipts_v1(receipt_id,root,artifact,stored_at) VALUES(?,?,?,?)`, id, root, artifact, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

type SignedReceiptRecord struct {
	Artifact        json.RawMessage `json:"artifact"`
	UploadState     string          `json:"upload_state"`
	UploadError     string          `json:"upload_error,omitempty"`
	Acknowledgement json.RawMessage `json:"acknowledgement,omitempty"`
	Root            string          `json:"root"`
}

func (s *Store) SignedReceipt(id string) (SignedReceiptRecord, error) {
	var r SignedReceiptRecord
	var acknowledgement []byte
	err := s.db.QueryRow(`SELECT artifact,root,upload_state,upload_error,acknowledgement FROM signed_change_receipts_v1 WHERE receipt_id=?`, id).Scan(&r.Artifact, &r.Root, &r.UploadState, &r.UploadError, &acknowledgement)
	r.Acknowledgement = acknowledgement
	return r, err
}
func (s *Store) ReceiptUploadOutcome(id, state, detail string, ack []byte) error {
	_, err := s.db.Exec(`UPDATE signed_change_receipts_v1 SET upload_state=?,upload_error=?,acknowledgement=? WHERE receipt_id=?`, state, detail, ack, id)
	return err
}
func (s *Store) CaptureOutcome(root, destination, head, id, state, detail string) error {
	_, err := s.db.Exec(`INSERT INTO receipt_capture_outcomes_v1(root,destination,head,receipt_id,state,detail,observed_at) VALUES(?,?,?,?,?,?,?)`, root, destination, head, id, state, detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) LatestReceiptOutcome(root string) (string, error) {
	rows, err := s.db.Query(`SELECT destination,receipt_id,state,detail FROM receipt_capture_outcomes_v1 WHERE id IN (SELECT MAX(id) FROM receipt_capture_outcomes_v1 WHERE root=? GROUP BY destination) ORDER BY id DESC LIMIT 5`, root)
	if err != nil {
		return "", err
	}
	type outcome struct{ dest, id, state, detail string }
	items := []outcome{}
	for rows.Next() {
		var item outcome
		if err = rows.Scan(&item.dest, &item.id, &item.state, &item.detail); err != nil {
			rows.Close()
			return "", err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "No receipt capture recorded", nil
	}
	results := []string{}
	for _, item := range items {
		result := item.state + " · " + item.dest
		if item.id != "" {
			var upload string
			if s.db.QueryRow(`SELECT upload_state FROM signed_change_receipts_v1 WHERE receipt_id=?`, item.id).Scan(&upload) == nil {
				result += " · upload " + upload
			}
			result += " · " + item.id
		}
		if item.detail != "" {
			result += " · " + item.detail
		}
		results = append(results, result)
	}
	return strings.Join(results, "\n"), nil
}
