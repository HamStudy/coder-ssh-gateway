package innerssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Feature extensions for the fake workspace SSH server: direct-tcpip dials,
// tcpip-forward listeners, agent forwarding, and the sftp subsystem. All
// activate only when a client exercises them, so existing fake-coder
// behavior is unchanged.

// directTCPIPMsg is the RFC 4254 §7.2 direct-tcpip payload.
type directTCPIPMsg struct {
	Addr     string
	Port     uint32
	Orig     string
	OrigPort uint32
}

// forwardTCPMsg is the OpenSSH tcpip-forward global request payload.
type forwardTCPMsg struct {
	Addr string
	Port uint32
}

// forwardedTCPMsg is the RFC 4254 §7.2 forwarded-tcpip payload.
type forwardedTCPMsg struct {
	Addr     string
	Port     uint32
	Orig     string
	OrigPort uint32
}

// forwardRegistry tracks tcpip-forward listeners so cancel-tcpip-forward
// can close the right one.
type forwardRegistry struct {
	mu        sync.Mutex
	listeners map[string]net.Listener
}

func newForwardRegistry() *forwardRegistry {
	return &forwardRegistry{listeners: map[string]net.Listener{}}
}

func (r *forwardRegistry) add(addr string, port uint32, l net.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners[addr+":"+strconv.Itoa(int(port))] = l
}

func (r *forwardRegistry) remove(addr string, port uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := addr + ":" + strconv.Itoa(int(port))
	if l, ok := r.listeners[key]; ok {
		_ = l.Close()
		delete(r.listeners, key)
	}
}

func (r *forwardRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.listeners {
		_ = l.Close()
	}
	r.listeners = map[string]net.Listener{}
}

// handleDirectTCPIP accepts and services one direct-tcpip open by dialing
// the real address from the test process. Dial failures reject the open
// with SSH_OPEN_CONNECT_FAILED, matching native sshd behavior.
func handleDirectTCPIP(newChan ssh.NewChannel) {
	var msg directTCPIPMsg
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		_ = newChan.Reject(ssh.Prohibited, "invalid payload")
		return
	}
	target := net.JoinHostPort(msg.Addr, strconv.Itoa(int(msg.Port)))
	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "connect failed")
		return
	}
	ch, requests, err := newChan.Accept()
	if err != nil {
		_ = upstream.Close()
		return
	}
	go drainReqs(requests)
	go func() {
		defer upstream.Close()
		defer ch.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(ch, upstream); done <- struct{}{} }()
		go func() { _, _ = io.Copy(upstream, ch); done <- struct{}{} }()
		<-done
	}()
}

const dialTimeout = 5 * time.Second

func drainReqs(requests <-chan *ssh.Request) {
	for req := range requests {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// handleGlobalRequests services keepalives, tcpip-forward, and
// cancel-tcpip-forward. Bind success replies with the bound port (RFC 4254
// §7.1) so port-0 requests work like native sshd.
func handleGlobalRequests(srvConn *ssh.ServerConn, reg *forwardRegistry, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "tcpip-forward":
			var msg forwardTCPMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			bindAddr := net.JoinHostPort(msg.Addr, strconv.Itoa(int(msg.Port)))
			if msg.Addr == "" {
				bindAddr = net.JoinHostPort("localhost", strconv.Itoa(int(msg.Port)))
			}
			l, err := net.Listen("tcp", bindAddr)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			bound := l.Addr().(*net.TCPAddr).Port
			if msg.Port != 0 {
				bound = int(msg.Port)
			}
			reg.add(msg.Addr, uint32(bound), l)
			go acceptForward(srvConn, l, msg.Addr, uint32(bound))
			if msg.Port == 0 {
				_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{uint32(bound)}))
			} else {
				_ = req.Reply(true, nil)
			}
		case "cancel-tcpip-forward":
			var msg forwardTCPMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				reg.remove(msg.Addr, msg.Port)
			}
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(req.Type == "keepalive@openssh.com", nil)
			}
		}
	}
}

// acceptForward turns each accepted connection on a -R listener into a
// forwarded-tcpip channel opened back to the client.
func acceptForward(srvConn *ssh.ServerConn, l net.Listener, addr string, port uint32) {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		payload := ssh.Marshal(forwardedTCPMsg{
			Addr: addr, Port: port, Orig: "127.0.0.1", OrigPort: 0,
		})
		ch, reqs, err := srvConn.OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			_ = conn.Close()
			continue
		}
		go drainReqs(reqs)
		go func() {
			defer conn.Close()
			defer ch.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(ch, conn); done <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, ch); done <- struct{}{} }()
			<-done
		}()
	}
}

// serveSFTP blocks serving the sftp subsystem with pkg/sftp rooted at the
// test process filesystem (tests pass absolute paths inside their tempdir).
// Returns when the client disconnects.
func serveSFTP(ch ssh.Channel) {
	server, err := sftp.NewServer(ch)
	if err != nil {
		return
	}
	_ = server.Serve()
}

// agentRequestIdentities uses an agent-forwarding channel opened toward the
// client to list identities, emulating a workspace process touching
// SSH_AUTH_SOCK. Returns a printable summary for exec output.
func agentRequestIdentities(srvConn *ssh.ServerConn) (string, error) {
	ch, reqs, err := srvConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return "", fmt.Errorf("agent channel refused: %w", err)
	}
	defer ch.Close()
	go drainReqs(reqs)

	// SSH_AGENTC_REQUEST_IDENTITIES (11); the length prefix is written below.
	msg := []byte{11}
	if err := binary.Write(ch, binary.BigEndian, uint32(len(msg))); err != nil {
		return "", err
	}
	if _, err := ch.Write(msg); err != nil {
		return "", err
	}
	var size uint32
	if err := binary.Read(ch, binary.BigEndian, &size); err != nil {
		return "", err
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(ch, body); err != nil {
		return "", err
	}
	if len(body) < 5 || body[0] != 12 {
		return fmt.Sprintf("agent-failure:op=%d:len=%d", body[0], len(body)), nil
	}
	nKeys := binary.BigEndian.Uint32(body[1:5])
	return fmt.Sprintf("agent-keys=%d", nKeys), nil
}
