package secure

import (
	"crypto/ecdh"
	"crypto/rand"
)

type KeyECDH struct {
	key *ecdh.PrivateKey
	pub *ecdh.PublicKey
}

var _ Key = &KeyECDH{}

func (k *KeyECDH) Generate() (aesKey []byte, encryptedKey []byte, err error) {
	remoteKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	aesKey, err = remoteKey.ECDH(k.pub)

	return aesKey, remoteKey.PublicKey().Bytes(), err
}

func (k *KeyECDH) Decrypt(encryptedKey []byte) (aesKey []byte, err error) {
	remoteKey, err := ecdh.X25519().NewPublicKey(encryptedKey)
	if err != nil {
		return nil, err
	}

	return k.key.ECDH(remoteKey)
}
