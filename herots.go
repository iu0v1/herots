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

////////////////////////////////////////////////////////////////////////////////
//                       Shared functions and structs                         //
////////////////////////////////////////////////////////////////////////////////

// log - struct for internal log service
type log struct {
	LogLevel       int
	LogDestination io.Writer
}

func (l *log) Log(msg string, lvl int) {
	if l.LogLevel == 0 {
		return
	}

	if l.LogLevel <= lvl {
		fmt.Fprintf(l.LogDestination, "herots: %s\n", msg)
	}
}

// loadKeyPair - internal function for load certificate and private key pair.
func loadKeyPair(cert, key []byte) (tls.Certificate, *x509.Certificate, error) {
	c, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, &x509.Certificate{}, err
	}

	pemData, _ := pem.Decode(cert)
	ca, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		return tls.Certificate{}, &x509.Certificate{}, err
	}

	return c, ca, nil
}

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
	//
	// This option ignored for client implementation.
	//
	// Default: tls.RequireAnyClientCert
	TLSAuthType tls.ClientAuthType
}

// predefined errors messages
const (
	LoadKeyPairError      = "herots: load key pair error"
	LoadClientCaCertError = "herots srv: load client CA cert error"
	StartServerError      = "herots srv: start tls server error"
	NoKeyPairLoad         = "herots: no load key pair (use LoadKeyPair func)"
	AcceptConnError       = "herots srv: connection accept error"
)

////////////////////////////////////////////////////////////////////////////////
//                                  Server                                    //
////////////////////////////////////////////////////////////////////////////////

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
	listener net.Listener
	logger   *log
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

	l := &log{
		LogLevel:       o.LogLevel,
		LogDestination: o.LogDestination,
	}

	s.options = o
	s.logger = l

	return s
}

// LoadKeyPair - function for load certificate and private key pair.
//
// Public/private key pair require as PEM encoded data.
func (s *Server) LoadKeyPair(cert, key []byte) error {
	c, ca, err := loadKeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("%s: %v\n", LoadKeyPairError, err)
	}

	s.certs.Cert = c

	s.certs.pool.Pool = x509.NewCertPool()
	s.certs.pool.Pool.AddCert(ca)
	s.certs.pool.IsSet = true

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

	s.logger.Log("load client CA cert ok", 2)

	return nil
}

// Accept - accept and return connections.
func (s *Server) Accept() (net.Conn, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		s.logger.Log("accept conn error: "+err.Error(), 3)
		return conn, fmt.Errorf("%s: %v\n", AcceptConnError, err)
	}
	s.logger.Log("accepted conn from "+conn.RemoteAddr().String(), 2)
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

	s.logger.Log("listening on "+service, 1)

	return nil
}

////////////////////////////////////////////////////////////////////////////////
//                                  Client                                    //
////////////////////////////////////////////////////////////////////////////////

// Client - primary struct for client implementation.
type Client struct{}

// NewClient - function for create Client struct
func NewClient(o *Options) *Client {}
