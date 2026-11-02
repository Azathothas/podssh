// The stand-in of an SSH server of Go's x/crypto/ssh, the library under
// gliderlabs/ssh, for scripts/interop-go-ssh.sh (T-460, GitHub #83 and #85).
// It answers each global request with data after the reply's type, as such
// servers do: a refused tcpip-forward with the words of gliderlabs/ssh, and
// each other request with 15 bytes, in a failure (-reply failure, the case
// of #83: a keepalive that the server does not know) or in a success
// (-reply success). It lets anyone in, and runs the command of each exec in
// /bin/sh, as a gateway's sandbox does; it writes a line for each global
// request on stderr, which the harness reads.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

var (
	// What gliderlabs/ssh gives a tcpip-forward that its server refuses.
	refusedForward = []byte("port forwarding is disabled")
	// The 15 bytes after the failure that #83's server sent.
	otherData = []byte("unknown request")
)

func main() {
	listen := flag.String("listen", "0.0.0.0:2222", "the address to listen on")
	reply := flag.String("reply", "failure", "the reply to each global request but tcpip-forward: failure or success")
	flag.Parse()
	log.SetFlags(0)
	if *reply != "failure" && *reply != "success" {
		log.Fatalf("-reply %q: failure or success", *reply)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("no host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatalf("no signer: %v", err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("listening on %s, global requests answered with %s and data", ln.Addr(), *reply)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go serve(conn, config, *reply == "success")
	}
}

func serve(conn net.Conn, config *ssh.ServerConfig, success bool) {
	defer conn.Close()
	server, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("handshake with %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("logged in: %s (%s)", server.User(), server.ClientVersion())
	go global(reqs, success)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.Prohibited, "only sessions")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go session(channel, requests)
	}
	log.Printf("the connection of %s ended", server.User())
}

// global answers each global request with data after the reply's type, as
// Request.Reply(ok, payload) sends it.
func global(reqs <-chan *ssh.Request, success bool) {
	for req := range reqs {
		ok, data := success, otherData
		if req.Type == "tcpip-forward" {
			ok, data = false, refusedForward
		}
		if !req.WantReply {
			log.Printf("global request %s: no reply asked", req.Type)
			continue
		}
		err := req.Reply(ok, data)
		log.Printf("global request %s: replied %v with %d bytes (%v)", req.Type, ok, len(data), err)
	}
}

// session runs the first exec of the channel, and refuses each other request.
func session(channel ssh.Channel, requests <-chan *ssh.Request) {
	started := false
	for req := range requests {
		var payload struct{ Command string }
		if req.Type == "exec" && !started && ssh.Unmarshal(req.Payload, &payload) == nil {
			started = true
			req.Reply(true, nil)
			go run(channel, payload.Command)
			continue
		}
		req.Reply(false, nil)
	}
}

// run gives the command's output, then its exit status, the end of its
// output and the close, in that order, as sshd does.
func run(channel ssh.Channel, command string) {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	status := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		status = 255
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			status = exit.ExitCode()
		}
	}
	channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{uint32(status)}))
	channel.CloseWrite()
	channel.Close()
	log.Printf("exec %q: exit %d", command, status)
}
