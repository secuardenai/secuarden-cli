// Package changereceipt implements the separate signed change-receipt v1
// protocol. It does not replace decision-ledger HMAC or local storage receipts.
package changereceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const ProtocolVersion = "secuarden.change-receipt/v1"

// SigningProvider keeps key custody independent of registration and receipts.
// Sign accepts the complete domain-prefixed canonical protocol message.
type SigningProvider interface {
	PublicKey() ed25519.PublicKey
	Sign(message []byte) ([]byte, error)
}

// EphemeralProvider owns a random private key in process memory only.
// It must be closed by its owner and is not safe for concurrent use.
type EphemeralProvider struct{ private ed25519.PrivateKey }

func NewEphemeralProvider() (*EphemeralProvider, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate receipt signing key: %w", err)
	}
	return &EphemeralProvider{private: private}, nil
}

func (p *EphemeralProvider) PublicKey() ed25519.PublicKey {
	if len(p.private) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), p.private[ed25519.SeedSize:]...)
}

func (p *EphemeralProvider) Sign(message []byte) ([]byte, error) {
	if len(p.private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("receipt signing key is closed")
	}
	return ed25519.Sign(p.private, message), nil
}

// Close clears the owned buffer on a best-effort basis. Go may retain runtime
// copies; this does not guarantee elimination from process memory.
func (p *EphemeralProvider) Close() { clear(p.private); p.private = nil }

func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return fmt.Sprintf("ed25519:sha256:%x", sum)
}
