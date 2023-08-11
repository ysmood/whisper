package whisper

import (
	"crypto/md5"
	"encoding/gob"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

type AgentReq struct {
	Version string
	Decrypt bool
	Config  Config
}

type AgentRes struct {
	Running         bool
	WrongPassphrase bool
}

var _ = func() int {
	gob.Register(AgentReq{})
	gob.Register(AgentRes{})

	return 0
}()

type AgentSever struct {
	listener net.Listener
	logger   *slog.Logger

	cache *privateKeyCache
}

func NewAgentServer() *AgentSever {
	return &AgentSever{
		logger: slog.Default(),
		cache: &privateKeyCache{
			cache: map[[md5.Size]byte]string{},
		},
	}
}

// Serve start a http server to avoid inputting the passphrase every time.
func (a *AgentSever) Serve(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	a.Listen(l)
}

// Serve start a http server to avoid inputting the passphrase every time.
func (a *AgentSever) Listen(l net.Listener) {
	a.listener = l

	for {
		conn, err := l.Accept()
		if err != nil {
			a.logger.Error("accept error", "err", err)
			break
		}

		go func() {
			s := piper.NewEnder(conn)
			defer func() { _ = s.Close() }()

			err := a.Handle(s)
			if err != nil {
				err := s.End([]byte(err.Error()))
				if err != nil {
					a.logger.Error("ender error", "err", err)
				}
			}
		}()
	}
}

func (a *AgentSever) Handle(s io.ReadWriteCloser) error { //nolint: cyclop,funlen
	b, err := byframe.NewScanner(s).Next()
	if err != nil {
		return err
	}

	req, err := decode[AgentReq](b)
	if err != nil {
		return err
	}

	if req.Version != "" {
		if req.Version == Version() {
			return a.res(s, AgentRes{Running: true})
		}

		return a.listener.Close()
	}

	a.cacheLoadPrivate(&req.Config)

	wsp, err := New(req.Config)
	if err != nil {
		if secure.IsAuthErr(err) {
			return a.res(s, AgentRes{WrongPassphrase: true})
		}

		return err
	}

	a.cachePrivate(req.Config.Private)

	err = a.res(s, AgentRes{})
	if err != nil {
		return err
	}

	if req.Decrypt {
		r, err := wsp.Decoder(io.NopCloser(s))
		if err != nil {
			return err
		}

		_, err = io.Copy(s, r)
		if err != nil {
			return err
		}

		return r.Close()
	}

	w, err := wsp.Encoder(piper.NopCloser(s))
	if err != nil {
		return err
	}

	_, err = io.Copy(w, s)
	if err != nil {
		return err
	}

	return w.Close()
}

func (a *AgentSever) cacheLoadPrivate(conf *Config) {
	if conf.Private.Passphrase != "" {
		return
	}

	key := md5.Sum(conf.Private.Data)
	if p, ok := a.cache.Get(key); ok {
		conf.Private.Passphrase = p
	}
}

func (a *AgentSever) cachePrivate(p PrivateKey) {
	key := md5.Sum(p.Data)
	a.cache.Set(key, p.Passphrase)
}

func (a *AgentSever) res(s io.Writer, res AgentRes) error {
	b, err := encode(res)
	if err != nil {
		return err
	}

	_, err = s.Write(byframe.Encode(b))
	return err
}

// Return true if the passphrase is correct.
func CallAgent(addr string, req AgentReq, in io.Reader, out io.Writer) bool {
	res, stream, err := agentReq(addr, req)
	if err != nil {
		panic(err)
	}

	defer func() { _ = stream.Close() }()

	if res.WrongPassphrase {
		return false
	}

	go func() {
		_, err := io.Copy(stream, in)
		if err != nil {
			panic(err)
		}

		err = stream.End(nil)
		if err != nil {
			panic(err)
		}
	}()

	_, err = io.Copy(out, stream)
	if err != nil {
		panic("your key might be wrong or data is corrupted: " + err.Error())
	}

	return true
}

func IsAgentRunning(addr, version string) bool {
	res, stream, err := agentReq(addr, AgentReq{Version: version})
	if err != nil {
		if stream == nil {
			return false
		}

		panic(err)
	}

	defer func() { _ = stream.Close() }()

	err = stream.End(nil)
	if err != nil {
		return false
	}

	return res.Running
}

func agentReq(addr string, req AgentReq) (*AgentRes, *piper.Ender, error) {
	conn, err := net.Dial("tcp", addr)
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

type privateKeyCache struct {
	lock  sync.Mutex
	cache map[[md5.Size]byte]string
}

func (p *privateKeyCache) Get(key [md5.Size]byte) (string, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()

	val, ok := p.cache[key]
	return val, ok
}

func (p *privateKeyCache) Set(key [md5.Size]byte, val string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.cache[key] = val
}
