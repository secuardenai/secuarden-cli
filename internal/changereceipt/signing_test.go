package changereceipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestEphemeralSigningLifecycle(t *testing.T) {
	p, err := NewEphemeralProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	other, err := NewEphemeralProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	public := p.PublicKey()
	if len(public) != 32 || bytes.Equal(public, other.PublicKey()) {
		t.Fatal("invalid or reused random public key")
	}
	sum := sha256.Sum256(public)
	if KeyID(public) != fmt.Sprintf("ed25519:sha256:%x", sum) {
		t.Fatal("wrong fingerprint")
	}
	message := []byte(ProtocolVersion + "\n{}")
	sig, err := p.Sign(message)
	if err != nil || !ed25519.Verify(public, message, sig) {
		t.Fatal("signature failed")
	}
	if ed25519.Verify(other.PublicKey(), message, sig) || ed25519.Verify(public, []byte("tampered"), sig) {
		t.Fatal("invalid signature accepted")
	}
	// A caller cannot mutate the provider's public-key buffer.
	p.PublicKey()[0] ^= 1
	if !bytes.Equal(public, p.PublicKey()) {
		t.Fatal("public key alias")
	}
	owned := p.private
	p.Close()
	if !bytes.Equal(owned, make([]byte, 64)) || p.PublicKey() != nil {
		t.Fatal("key buffer not cleared")
	}
	if _, err := p.Sign(message); err == nil {
		t.Fatal("closed key signed")
	}
	p.Close()
}
