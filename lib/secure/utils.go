package secure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func PublicKeyHash(pub crypto.PublicKey) []byte {
	h := sha1.New()
	var d []byte

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		d = h.Sum(append(key.X.Bytes(), key.Y.Bytes()...))
	case ed25519.PublicKey:
		d = h.Sum(key)
	case *rsa.PublicKey:
		d = h.Sum(key.N.Bytes())
	}

	return d[:sha1.Size]
}

func PublicKeyHashByPrivateKey(prv crypto.PrivateKey) []byte {
	return PublicKeyHash(prv.(crypto.Signer).Public())
}

func NewCipherBytes(privateKey []byte, passphrase string, index int, publicKeys ...[]byte) (*Cipher, error) {
	prv, pubs, err := bytesToKeys(privateKey, passphrase, publicKeys)
	if err != nil {
		return nil, err
	}

	return NewCipher(prv, index, pubs...), nil
}

func NewSignerBytes(privateKey []byte, passphrase string, publicKeys ...[]byte) (*Signer, error) {
	prv, pubs, err := bytesToKeys(privateKey, passphrase, publicKeys)
	if err != nil {
		return nil, err
	}

	var pub crypto.PublicKey
	if len(pubs) > 0 {
		pub = pubs[0]
	}

	return NewSigner(prv, pub), nil
}

func bytesToKeys(private []byte, passphrase string, publics [][]byte) (crypto.PrivateKey, []crypto.PublicKey, error) {
	var prv crypto.PrivateKey

	if private != nil {
		var err error
		prv, err = SSHPrvKey(private, passphrase)
		if err != nil {
			return nil, nil, err
		}
	}

	pubs := []crypto.PublicKey{}
	for _, publicKey := range publics {
		key, err := SSHPubKey(publicKey)
		if err != nil {
			return nil, nil, err
		}

		pubs = append(pubs, key)
	}

	return prv, pubs, nil
}

// GenerateKeyFile generates a new ssh key pair.
func GenerateKeyFile(privateKeyPath, comment, passphrase string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return err
	}

	pubKeyString := fmt.Sprintf("%s %s %s\n",
		sshPubKey.Type(),
		base64.StdEncoding.EncodeToString(sshPubKey.Marshal()),
		comment,
	)
	err = os.WriteFile(privateKeyPath+".pub", []byte(pubKeyString), 0o644)
	if err != nil {
		return err
	}

	prvKeyPem, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, comment, []byte(passphrase))
	if err != nil {
		return err
	}

	prvKeyBytes := pem.EncodeToMemory(prvKeyPem)

	return os.WriteFile(privateKeyPath, prvKeyBytes, 0o600)
}
