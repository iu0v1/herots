// Package herots provide fast way to create TLS services: server and client.
//
// Explanation of the name: HERald Of The Swarm
//
// By the way - have a nice day :)
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

// Server - primary struct for server implementation.
type Server struct {
	options *Options
	certs   struct {
		Cert tls.Certificate
		pool struct {
			IsSet bool
			Pool  *x509.CertPool
		}
	}
	listener       net.Listener
	logDestination io.Writer
}

// predefined errors messages
const (
	LoadKeyPairError      = "herots: load key pair error"
	LoadClientCaCertError = "herots srv: load client CA cert error"
	StartServerError      = "herots srv: start tls server error"
	NoKeyPairLoad         = "herots: no load key pair (use LoadKeyPair func)"
	AcceptConnError       = "herots srv: connection accept error"
)

// Options - structure, which is used to configure a TLS server and client.
type Options struct {
	// Server host.
	//
	// Default: '127.0.0.1'.
	Host string

	// Server port.
	//
	// Default: '9000'.
	Port int

	// LogLevel provides the opportunity to choose the level of
	// information messages.
	// Each level includes the messages from the previous level.
	// 0 - no messages
	// 1 - notice
	// 2 - info
	// 3 - error
	//
	// Default: '0'.
	LogLevel int

	// LogDestination provides the opportunity to choose the own
	// destination for log messages (errors, info, etc).
	//
	// Default: 'os.Stdout'.
	LogDestination io.Writer

	// TLSAuthType - refer to http://golang.org/pkg/crypto/tls/#ClientAuthType
	// Default: tls.RequireAnyClientCert
	TLSAuthType tls.ClientAuthType
}

// NewServer - function for create Server struct
func NewServer(o *Options) *Server {
	s := &Server{}

	// check mandatory options
	if o.LogDestination == nil {
		o.LogDestination = os.Stdout
	}

	if o.Port == 0 {
		o.Port = 9000
	}

	if o.TLSAuthType == 0 {
		o.TLSAuthType = tls.RequireAnyClientCert
	}

	s.options = o

	return s
}

// log - function for print log messages
func (s *Server) log(m string, lvl int) {
	if s.options.LogLevel == 0 {
		return
	}

	if s.options.LogLevel <= lvl {
		fmt.Fprintf(s.logDestination, "herots srv: %s\n", m)
	}
}

// LoadKeyPair - function for load certificate and private key pair.
//
// Public/private key pair require as PEM encoded data.
func (s *Server) LoadKeyPair(cert, key []byte) error {
	// create cert pool
	s.certs.pool.Pool = x509.NewCertPool()

	// load keypair
	c, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadKeyPairError, err)
	}
	s.certs.Cert = c

	// add cert to pool
	pemData, _ := pem.Decode(cert)
	ca, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadKeyPairError, err)
	}
	s.certs.pool.Pool.AddCert(ca)
	s.certs.pool.IsSet = true

	s.log("load key pair ok", 2)

	return nil
}

// AddClientCACert - function for adding client CA certificate to
// x509.CertPool (tls.Config.ClientCAs).
//
// By default server add cert from server public/private key pair (LoadKeyPair)
// to cert pool.
func (s *Server) AddClientCACert(cert []byte) error {
	pemData, _ := pem.Decode(cert)
	ca, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadClientCaCertError, err)
	}
	s.certs.pool.Pool.AddCert(ca)

	s.log("load client CA cert ok", 2)

	return nil
}

// Accept - accept and return connections.
func (s *Server) Accept() (net.Conn, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		s.log("accept conn error: "+err.Error(), 3)
		return conn, fmt.Errorf("%s: %v\n", AcceptConnError, err)
	}
	s.log("accepted conn from "+conn.RemoteAddr().String(), 2)
	return conn, nil
}

// Start - function for start server.
func (s *Server) Start() error {
	// load keypair check
	if len(s.certs.Cert.Certificate) == 0 {
		return fmt.Errorf("%s\n", NoKeyPairLoad)
	}

	config := tls.Config{
		ClientAuth:   s.options.TLSAuthType,
		Certificates: []tls.Certificate{s.certs.Cert},
		ClientCAs:    s.certs.pool.Pool,
		Rand:         rand.Reader,
	}

	service := s.options.Host + ":" + strconv.Itoa(s.options.Port)

	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		return fmt.Errorf("%s: %v\n", StartServerError, err)
	}
	s.listener = listener

	s.log("listening on "+service, 2)

	return nil
}
