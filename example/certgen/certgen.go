package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func sha1pub(pub *rsa.PublicKey) ([]byte, error) {
	pkixPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pubkey: %v\n", err)
	}

	h := sha1.New()
	h.Write(pkixPub)
	return h.Sum(nil), nil
}

func main() {

	name := pkix.Name{
		CommonName:         "localhost", // FQDN name!
		Country:            []string{"Shambala"},
		Organization:       []string{"ZEN"},
		OrganizationalUnit: []string{"Om 0"},
		Province:           []string{"sham 0"},
		Locality:           []string{"UA"},
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	keyID, err := sha1pub(pub)
	if err != nil {
		fmt.Println(err)
		return
	}

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1000),
		SubjectKeyId:          keyID,
		Subject:               name,
		NotBefore:             time.Now().Local(),
		NotAfter:              time.Now().AddDate(10, 0, 0).Local(),
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca.IPAddresses = append(ca.IPAddresses, net.ParseIP("127.0.0.1"))
	ca.DNSNames = append(ca.DNSNames, "localhost")

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}
	ca_f := "ca.pem"
	log.Println("write to", ca_f)
	crtFile, _ := os.Create(ca_f)
	pem.Encode(crtFile, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	crtFile.Close()

	priv_f := "ca.key"
	priv_b := x509.MarshalPKCS1PrivateKey(priv)
	log.Println("write to", priv_f)
	crtFile, _ = os.Create(priv_f)
	pem.Encode(crtFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: priv_b})
	crtFile.Close()

	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub2 := &priv2.PublicKey

	keyID2, err := sha1pub(pub2)
	if err != nil {
		fmt.Println(err)
		return
	}

	cert2 := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		SubjectKeyId:          keyID2,
		Subject:               name,
		NotBefore:             time.Now().Local(),
		NotAfter:              time.Now().AddDate(10, 0, 0).Local(),
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	cert2.IPAddresses = append(ca.IPAddresses, net.ParseIP("127.0.0.1"))
	cert2.DNSNames = append(ca.DNSNames, "localhost")

	cert2_b, err2 := x509.CreateCertificate(rand.Reader, cert2, ca, pub2, priv)
	if err2 != nil {
		log.Println("create cert2 failed", err2)
		return
	}

	cert2_f := "cert2.pem"
	log.Println("write to", cert2_f)
	crtFile, _ = os.Create(cert2_f)
	pem.Encode(crtFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert2_b})
	crtFile.Close()

	priv2_f := "cert2.key"
	priv2_b := x509.MarshalPKCS1PrivateKey(priv2)
	log.Println("write to", priv2_f)
	crtFile, _ = os.Create(priv2_f)
	pem.Encode(crtFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: priv2_b})
	crtFile.Close()

	ca_c, _ := x509.ParseCertificate(ca_b)
	cert2_c, _ := x509.ParseCertificate(cert2_b)

	err3 := cert2_c.CheckSignatureFrom(ca_c)
	log.Println("check signature", err3 == nil)
}
