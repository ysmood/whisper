package secure

import (
	"crypto"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

const PUB_KEY_EXT = ".pub"

const KEY_HASH_SIZE = md5.Size

func PublicKeyHash(pub crypto.PublicKey) ([]byte, error) {
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}

	d := md5.Sum(sshPubKey.Marshal())

	return d[:], nil
}

func PublicKeyHashByPrivateKey(prv crypto.PrivateKey) ([]byte, error) {
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

// GenerateKeyFile generates a new ed25519 ssh key pair.
// If deterministic is true, the key will be generated based on the passphrase itself,
// so the same passphrase will always generate the same key, this is useful if you don't want to backup the key,
// but it's less secure, you must use a strong passphrase.
func GenerateKeyFile(deterministic bool, privateKeyPath, comment, passphrase string) error {
	seed := rand.Reader

	if deterministic {
		salt := sha256.Sum256([]byte(passphrase))
		derivedKey := argon2.IDKey([]byte(passphrase), salt[:], 128, 64*1024, 4, 32)
		seed = hkdf.New(sha256.New, derivedKey, nil, nil)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(seed)
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
	err = os.WriteFile(privateKeyPath+PUB_KEY_EXT, []byte(pubKeyString), 0o644)
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
