package whisper

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/sync/errgroup"
)

var ErrWrongPublicKey = errors.New("the public key from option -a doesn't belong to the private key")

type AgentClient struct {
	Addr string
}

func NewAgentClient(addr string) *AgentClient {
	return &AgentClient{Addr: addr}
}

// Return true if the passphrase is correct.
func (c *AgentClient) CallAgent(req AgentReq, in io.Reader, out io.Writer) error {
	res, stream, err := c.agentReq(req)
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
			if strings.Contains(err.Error(), secure.ErrSignNotMatch.Error()) {
				err = secure.ErrSignNotMatch
			}

			return err
		}

		return nil
	})

	return eg.Wait()
}

func (c *AgentClient) IsPassphraseRight(prv PrivateKey) (bool, error) {
	res, stream, err := c.agentReq(AgentReq{CheckPassphrase: true, Config: Config{Private: &prv}})
	if err != nil {
		if stream == nil {
			return false, nil
		}

		return false, err
	}

	_ = stream.Close()

	return res.PassphraseRight, nil
}

func (c *AgentClient) IsAgentRunning(version string) (bool, error) {
	res, stream, err := c.agentReq(AgentReq{Version: version})
	if err != nil {
		if stream == nil {
			return false, nil
		}

		return false, err
	}

	_ = stream.Close()

	return res.Running, nil
}

func (c *AgentClient) ClearCache() error {
	_, _, err := c.agentReq(AgentReq{ClearCache: true})
	return err
}

func (c *AgentClient) agentReq(req AgentReq) (*AgentRes, *piper.Ender, error) {
	conn, err := net.Dial("tcp", c.Addr)
	if err != nil {
		return nil, nil, err
	}

	e := piper.NewEnder(conn)

	b, err := encode(req)
	if err != nil {
		return nil, nil, err
	}

	_, err = e.Write(byframe.Encode(b))
	if err != nil {
		return nil, nil, err
	}

	b, err = byframe.NewScanner(e).Next()
	if err != nil {
		return nil, nil, err
	}

	res, err := decode[AgentRes](b)
	return &res, e, err
}
