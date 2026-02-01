package migration

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestGenerateKeypairWithRand(t *testing.T) {
	r := bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	kp, err := GenerateKeypairWithRand(r)
	if err != nil {
		t.Fatalf("GenerateKeypairWithRand returned error: %v", err)
	}

	priv, err := base64.StdEncoding.DecodeString(kp.PrivateKeyBase64)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(kp.PublicKeyBase64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("expected private key length 32, got %d", len(priv))
	}
	if len(pub) != 32 {
		t.Fatalf("expected public key length 32, got %d", len(pub))
	}
}
