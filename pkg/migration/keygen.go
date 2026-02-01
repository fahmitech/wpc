package migration

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type Keypair struct {
	PrivateKeyBase64 string
	PublicKeyBase64  string
}

func GenerateKeypair() (*Keypair, error) {
	return GenerateKeypairWithRand(rand.Reader)
}

func GenerateKeypairWithRand(r io.Reader) (*Keypair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(r)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	pub := priv.PublicKey()
	return &Keypair{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(pub.Bytes()),
	}, nil
}
