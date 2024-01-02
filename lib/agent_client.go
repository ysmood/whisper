package whisper

import (
	"errors"
	"io"

	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/sync/errgroup"
)

var ErrWrongPublicKey = errors.New("the public key from option -a doesn't belong to the private key")

// Return true if the passphrase is correct.
func CallAgent(addr string, req AgentReq, in io.Reader, out io.Writer) error {
	res, stream, err := agentReq(addr, req)
	if err != nil {
		return err
	}

	defer func() { _ = stream.Close() }()

	if res.WrongPublicKey {
		return ErrWrongPublicKey
	}

	eg := &errgroup.Group{}

	eg.Go(func() error {
		_, err := io.Copy(stream, in)
		if err != nil {
			return err
		}

		return stream.End(nil)
	})

	eg.Go(func() error {
		_, err = io.Copy(out, stream)
		if err != nil {
			if err.Error() == secure.ErrSignNotMatch.Error() {
				err = secure.ErrSignNotMatch
			}

			return err
		}

		return nil
	})

	return eg.Wait()
}

func IsPassphraseRight(addr string, prv PrivateKey) (bool, error) {
	res, stream, err := agentReq(addr, AgentReq{CheckPassphrase: true, Config: Config{Private: &prv}})
	if err != nil {
		if stream == nil {
			return false, nil
		}

		return false, err
	}

	_ = stream.Close()

	return res.PassphraseRight, nil
}

func IsAgentRunning(addr string, version byte) (bool, error) {
	res, stream, err := agentReq(addr, AgentReq{Version: version})
	if err != nil {
		if stream == nil {
			return false, nil
		}

		return false, err
	}

	_ = stream.Close()

	return res.Running, nil
}

func ClearCache(addr string) error {
	_, _, err := agentReq(addr, AgentReq{ClearCache: true})
	return err
}
