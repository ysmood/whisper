package whisper

import (
	"crypto/md5"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

type AgentReq struct {
	Version         string
	CheckPassphrase bool
	ClearCache      bool

	Config Config
}

type AgentRes struct {
	Running         bool
	PassphraseRight bool
	WrongPublicKey  bool
}

type AgentErrorType int

const (
	AgentErrorTypeOthers AgentErrorType = iota
	AgentErrorTypeSignMismatch
)

type AgentError struct {
	Type    AgentErrorType
	Message string
}

func (e AgentError) Error() string {
	return e.Message
}

// AgentServer is a tcp server that can be used to avoid inputting the passphrase every time.
// It will do the encryption and decryption for you, not the agent client.
// There's no way to get the passphrase from the tcp client, the only way to get the passphrase is
// to have root permission and dump the os memory.
// If the server restarts you have to send it to server again.
type AgentServer struct {
	Logger *slog.Logger

	listener net.Listener
	cache    *privateKeyCache
}

func NewAgentServer() *AgentServer {
	return &AgentServer{
		Logger: slog.Default(),
		cache: &privateKeyCache{
			cache: map[[md5.Size]byte]string{},
		},
	}
}

// Serve start a http server to avoid inputting the passphrase every time.
func (a *AgentServer) Serve(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	a.Listen(l)
}

// Serve start a http server to avoid inputting the passphrase every time.
func (a *AgentServer) Listen(l net.Listener) {
	a.listener = l

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				a.Logger.Info("listener closed")
				return
			}

			a.Logger.Warn("accept error", "err", err)
			continue
		}

		go func() {
			s := piper.NewEnder(conn)
			defer func() { _ = s.Close() }()

			err := a.Handle(s)
			if err != nil {
				typ := AgentErrorTypeOthers
				if errors.Is(err, secure.ErrSignMismatch) {
					typ = AgentErrorTypeSignMismatch
				}

				err := s.End(AgentError{Type: typ, Message: err.Error()})
				if err != nil {
					a.Logger.Warn("ender error", "err", err)
				}
			}
		}()
	}
}

func (a *AgentServer) Handle(s io.ReadWriteCloser) error {
	b, err := byframe.NewScanner(s).Next()
	if err != nil {
		return err
	}

	req, err := decode[AgentReq](b)
	if err != nil {
		return err
	}

	if req.Version != "" {
		return a.handleCheckVersion(s, req.Version)
	}

	if req.ClearCache {
		return a.handleClearCache(s)
	}

	a.cacheLoadPrivate(&req.Config)

	if req.CheckPassphrase {
		return a.handleCheckPassphrase(s, *req.Config.Private)
	}

	return a.handleWhisper(s, req)
}

func (a *AgentServer) handleCheckVersion(s io.ReadWriteCloser, version string) error {
	if version == APIVersion {
		return a.res(s, AgentRes{Running: true})
	}

	a.Logger.Warn("version mismatch, close server", "server", WireFormatVersion, "client", version)
	return a.listener.Close()
}

func (a *AgentServer) handleClearCache(s io.ReadWriteCloser) error {
	a.cache.Clear()
	return a.res(s, AgentRes{})
}

func (a *AgentServer) handleCheckPassphrase(s io.ReadWriteCloser, prv PrivateKey) error {
	right, err := IsPassphraseRight(prv)
	if err != nil {
		return err
	}

	a.cachePrivate(prv)

	return a.res(s, AgentRes{PassphraseRight: right})
}

func (a *AgentServer) handleWhisper(s io.ReadWriteCloser, req AgentReq) error {
	wsp := New(req.Config)

	if req.Config.Private != nil {
		a.cachePrivate(*req.Config.Private)
	}

	err := a.res(s, AgentRes{})
	if err != nil {
		return err
	}

	if req.Config.IsDecryption() {
		r, err := wsp.Decoder(s)
		if err != nil {
			return err
		}

		_, err = io.Copy(s, r)
		if err != nil {
			return err
		}

		return r.Close()
	}

	w, err := wsp.Encoder(s)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, s)
	if err != nil {
		return err
	}

	return w.Close()
}

func (a *AgentServer) cacheLoadPrivate(conf *Config) {
	if conf.Private == nil || conf.Private.Passphrase != "" {
		return
	}

	key := md5.Sum(conf.Private.Data)
	if p, ok := a.cache.Get(key); ok {
		conf.Private.Passphrase = p
	}
}

func (a *AgentServer) cachePrivate(p PrivateKey) {
	key := md5.Sum(p.Data)
	a.cache.Set(key, p.Passphrase)
}

func (a *AgentServer) res(s io.Writer, res AgentRes) error {
	b, err := encode(res)
	if err != nil {
		return err
	}

	_, err = s.Write(byframe.Encode(b))
	return err
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

func (p *privateKeyCache) Clear() {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.cache = map[[md5.Size]byte]string{}
}
