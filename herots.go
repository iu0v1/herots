/*
	HEROTS
	HERald Of The Swarm

	Package for fast TLS server creation.
*/
package herots

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

type HerotsSrv struct {
	options *HerotsSrvOptions
	certs   struct {
		Cert tls.Certificate
		pool struct {
			IsSet bool
			Pool  *x509.CertPool
		}
	}
	listener    net.Listener
	messagesDst io.Writer
}

// predefined errors messages
const (
	LoadKeyPairError      string = "herots: load key pair error"
	LoadClientCaCertError string = "herots srv: load client CA cert error"
	StartServerError      string = "herots srv: start tls server error"
	NoKeyPairLoad         string = "herots: no load key pair (use LoadKeyPair func)"
	AcceptConnError       string = "herots srv: connection accept error"
)

/*
	A HerotsSrvOptions structure is used to configure a TLS server.
*/
type HerotsSrvOptions struct {
	// Server host.
	// By default server use "127.0.0.1".
	Host string

	// Server port.
	// By default server use "9000".
	Port int

	// Message level provides the opportunity to choose
	// what print to the output.
	//   0 - no messages
	//   1 - errors
	//   2 - info messages
	//   3 - all ("1" + "2")
	// By default server use "2".
	MessageLvl int

	// See http://golang.org/pkg/crypto/tls/#ClientAuthType
	// By default server use tls.RequireAnyClientCert
	TlsAuthType tls.ClientAuthType
}

/*
	Return HerotsSrv struct with predefined options.
*/
func NewServer() *HerotsSrv {
	s := &HerotsSrv{
		options: &HerotsSrvOptions{
			Host:        "127.0.0.1",
			Port:        9000,
			MessageLvl:  2,
			TlsAuthType: tls.RequireAnyClientCert,
		},
	}
	s.messagesDst = os.Stdout // send msg to stdout by default

	return s
}

// func for print messages
func (h *HerotsSrv) msg(m string, lvl int) {
	if h.options.MessageLvl == 0 {
		return
	}

	if h.options.MessageLvl == 3 || h.options.MessageLvl == lvl {
		fmt.Fprintf(h.messagesDst, "herots srv: %s\n", m)
	}
}

/*
	Provides the opportunity to choose own destination for
	herots messages (errors, info, etc).

	By default server use os.Stdout.
*/
func (h *HerotsSrv) SetMessagesDst(src io.Writer) {
	h.messagesDst = src
}

/*
	Set herots server options (*HerotsSrvOptions).
*/
func (h *HerotsSrv) SetOptions(o *HerotsSrvOptions) {
	// check mandatory options
	if o.Port == 0 {
		h.msg("port can't be '0'", 2)
		h.msg("set port by default (9000)", 2)
		o.Port = 9000
	}

	h.options = o
}

/*
	Func for load certificate and private key pair.

	Public/private key pair require as PEM encoded data.
*/
func (h *HerotsSrv) LoadKeyPair(cert, key []byte) error {
	// create cert pool
	h.certs.pool.Pool = x509.NewCertPool()

	// load keypair
	c, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadKeyPairError, err)
	}
	h.certs.Cert = c

	// add cert to pool
	pemData, _ := pem.Decode(cert)
	ca, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadKeyPairError, err)
	}
	h.certs.pool.Pool.AddCert(ca)
	h.certs.pool.IsSet = true

	h.msg("load key pair ok", 2)

	return nil
}

/*
	Add client CA certificate to x509.CertPool (tls.Config.ClientCAs).

	By default server add cert from server public/private key pair (LoadKeyPair)
	to cert pool.
*/
func (h *HerotsSrv) AddClientCaCert(cert []byte) error {
	pemData, _ := pem.Decode(cert)
	ca, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadClientCaCertError, err)
	}
	h.certs.pool.Pool.AddCert(ca)

	h.msg("load client CA cert ok", 2)

	return nil
}

/*
	Accept and return connection to server.
*/
func (h *HerotsSrv) Accept() (net.Conn, error) {
	conn, err := h.listener.Accept()
	if err != nil {
		h.msg("accept conn error: "+err.Error(), 1)
		return conn, fmt.Errorf("%s: %v\n", AcceptConnError, err)
	}
	h.msg("accepted conn from "+conn.RemoteAddr().String(), 2)
	return conn, nil
}

/*
	Start server.
*/
func (h *HerotsSrv) Start() error {
	// load keypair check
	if len(h.certs.Cert.Certificate) == 0 {
		return fmt.Errorf("%s\n", NoKeyPairLoad)
	}

	config := tls.Config{
		ClientAuth:   h.options.TlsAuthType,
		Certificates: []tls.Certificate{h.certs.Cert},
		ClientCAs:    h.certs.pool.Pool,
		Rand:         rand.Reader,
	}

	service := h.options.Host + ":" + strconv.Itoa(h.options.Port)

	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		return fmt.Errorf("%s: %v\n", StartServerError, err)
	}
	h.listener = listener

	h.msg("listening on "+service, 2)

	return nil
}
