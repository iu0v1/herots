package main

import (
	"crypto/tls"
	"fmt"
	"github.com/SpiritOfStallman/herots"
	//"io/ioutil"
)

func main() {
	var err error

	//ca, _ := ioutil.ReadFile("certs/ca.pem")
	//key, _ := ioutil.ReadFile("certs/ca.key")

	herald := herots.NewServer()

	optinons := &herots.Options{
		//Host: "127.0.0.1",
		Host:         "localhost",
		Port:         9000,
		MessageLevel: 3,
		TLSAuthType:  tls.RequireAndVerifyClientCert,
		//TLSAuthType: tls.RequireAnyClientCert,
		//TLSAuthType: tls.VerifyClientCertIfGiven,
	}
	herald.Config(optinons)

	err = herald.LoadKeyPair([]byte(certPem), []byte(pkey))
	if err != nil {
		fmt.Println(err)
		return
	}

	//err = herald.LoadRootCaCert([]byte(certPem))
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}

	err = herald.Start()
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		conn, err := herald.Accept()
		defer conn.Close()
		if err != nil {
			fmt.Println(err)
			continue
		}

		for {
			buf := make([]byte, 512)

			n, err := conn.Read(buf)
			if err != nil {
				if err.Error() == "EOF" {
					fmt.Printf("from client: %s send EOF\n", conn.RemoteAddr())
				} else {
					fmt.Println("err::" + err.Error())
				}
				break
			}

			fmt.Printf("from client: %s\n", string(buf[:n]))

			n, err = conn.Write(buf[:n])
			if err != nil {
				fmt.Println(err)
				break
			}
			fmt.Printf("to client: %s\n", string(buf[:n]))
		}
	}
}

const certPem = `-----BEGIN CERTIFICATE-----
MIID3DCCAsagAwIBAgICBnUwCwYJKoZIhvcNAQELMGIxETAPBgNVBAYTCFNoYW1i
YWxhMQwwCgYDVQQKEwNaRU4xDTALBgNVBAsTBE9tIDAxCzAJBgNVBAcTAlVBMQ8w
DQYDVQQIEwZzaGFtIDAxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNDEyMjkxNDU0
MTBaFw0yNDEyMjkxNDU0MTBaMGIxETAPBgNVBAYTCFNoYW1iYWxhMQwwCgYDVQQK
EwNaRU4xDTALBgNVBAsTBE9tIDAxCzAJBgNVBAcTAlVBMQ8wDQYDVQQIEwZzaGFt
IDAxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAK3MZTm4lfof0th7T1WN1jN+WEfIPviCy73NB1iWZ5c9ut2Jqiy6ZX/g
XCMR7V/EMYKK6I4HD2MT1AowbK0W+dahEhftcyQx/pVJInF70wPtxuEjI6c38POW
zz73iMAombAh09+M2bcCgL9l6nQZf+V14xeKI4caWEsTb2RSr8pwPloJMQ2dwLeZ
bV4sCCtvK7WYGOWxbnaIq9F/f9Qsycue7z2413E3wcF93i2/uGeYd8/Iu0j5Y5mL
OjSWOqNJTzHsGraPZAXqdERF8gddKNx/I+E9ZWorvT96nkEonEjP5aFajBn1gWYo
WwCpLq0PXm9JixOvcHU8FgTCoETToD8CAwEAAaOBnzCBnDAOBgNVHQ8BAf8EBAMC
AIQwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFLbPqUht4U+mq/1jkykMq2B0h9xXMB8GA1UdIwQYMBaAFLbP
qUht4U+mq/1jkykMq2B0h9xXMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAL
BgkqhkiG9w0BAQsDggEBAHLdgxqk0IBiDNcm9VYZvsjQ6qcday4KAVgX4M4c3iQQ
CpRy7LfO5KTVFh0V0uQiHsCgj2GAmydcj80aTRI5g7FEmLq2RDsExT7b+YUuPdbJ
eH8HRxFJ+CZ8KPX6URRUMEfZsQT3Ya+5MepHt+MUW6afzgmCT7Ygnq34Wz+OqeU9
yu/ULk9lflRg1WtCwV9xt/C1TacJBsgURJKgfvnY9EiPFgnj6vIEkT9EvvOve2yJ
nsErKkQzQFmnv1CVtosdXkrlqoap0yRHjLECx1LXowM9sPWrnzE4meAuV5ItJAJ+
UkiHeEkqlHgjknTTz0CLfCqQohqZo3YSGJI9zPRBxLg=
-----END CERTIFICATE-----`

const pkey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArcxlObiV+h/S2HtPVY3WM35YR8g++ILLvc0HWJZnlz263Ymq
LLplf+BcIxHtX8QxgorojgcPYxPUCjBsrRb51qESF+1zJDH+lUkicXvTA+3G4SMj
pzfw85bPPveIwCiZsCHT34zZtwKAv2XqdBl/5XXjF4ojhxpYSxNvZFKvynA+Wgkx
DZ3At5ltXiwIK28rtZgY5bFudoir0X9/1CzJy57vPbjXcTfBwX3eLb+4Z5h3z8i7
SPljmYs6NJY6o0lPMewato9kBep0REXyB10o3H8j4T1laiu9P3qeQSicSM/loVqM
GfWBZihbAKkurQ9eb0mLE69wdTwWBMKgRNOgPwIDAQABAoIBAB24USsQtJzkKkMY
uxVPPuzpUyFbTeFjRIH9eJ8egTJsvPK7Yt1pNogqjrb0jtoMi8beCCyZankv39eq
NjtXLXwVaSmsUj9DSVyv9/LeENSgKZ1ATA2BVHPjOydyXvE1QCrNbhTRWj2gcPHJ
9NDLt4I+qYnR9odY6vZTqX3HYgZE6UtM8L2MJ2pjeQXaOHw1gexN0dFgCQHoWub2
OtD2qVdeuMjEgAwXJs3ZtLmuWZmUUl61UlddVEAv2Z1+Sx7xxDIyFV1MfAOEhL7k
sRpYvvAtoasq62lpbGht3pw1vH2SR0fXO+mWo6uVaohcviZCyNo67O5dgy76Z7vE
hyyBWcECgYEAzfMnCrzQBNeL0LX9VcUXFgCyDawW/qzVKBt9t43wvq2oG+6udDXp
ELfiA9kofXrPxfj7JADJVrSjiKhCrOEva5PSADwCs+8BHjvJ6TEKQEiKUfRAIxax
guZRZeSyQp/SUCqGxU2Swho6idnOhjouj0xCOVtGLGTNEjGH5rLxNh8CgYEA2Aj+
bZ6zQoWBsKMVOChk9xQi6tRSRG72CYpChimlr0m6ynUXHYZLxSOjVQiRZhl9PvBT
W44YKl9dBN7/LlaPOs9GucDXK9ojJTViMwbv2vcghZzAcCoFe25Ue9B5KrArIspO
YT440x5+FwKkU3NKdG1u0QozjL0uSOu722BlEeECgYB1G7itoGPg/Pgh+/pMFUBl
YIvevmZs9rZWkhtQjsPAiVq4V2aX6jfXK9i3O3qMr5MKDeQwusnCJgF/qb4QNBQU
5f9Z5sXaryNBn9nWYe5kU1tj8rGtwi+6MWFDwWGkBOFAeI4eD1hOSz/SNyn6pYbo
MQLPPpmOkNsTZ1rR0hrbHQKBgDUeMQDfDpCCpxq5XpRKSlj+GH/I6NlutwwtdKHs
R5LL/COfmqllxeeZFaXoz2ddSRBaowRV8dcpT4PNGM1Z9ymsoWU25zEfF5kkgRqu
z/b04Ig5vI9XpbVtsVQoNEKswk5xk8gRNoOicbpSqfji1iG+borziS1HrsO7Qpt0
HiXBAoGAUvEEMOZHqrl2LHNUdNpZwnfuBIVED5Waq6L/QPlZ1V95Qa44bafgG7a5
k3qBT55XyD0ttL1eXJQc6UzhmGHg3Kul7mBr9umn8GihziZP6j6oOFn5Lfq+jX2y
Ie9gPsYMqX2GQ47JgaNRdaN/8+tHZyTYNufVR6zCfLmDnv6+qI0=
-----END RSA PRIVATE KEY-----`
