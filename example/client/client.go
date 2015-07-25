package main

import (
	"io"
	"log"
	"os"
	"strconv"

	"github.com/iu0v1/herots"
)

func main() {

	options := &herots.Options{
		Host:           "localhost",
		Port:           9001,
		LogLevel:       herots.LogLevelError,
		LogDestination: os.Stdout, // for example
	}

	client := herots.NewClient(options)

	err := client.LoadKeyPair([]byte(certPem), []byte(pkey))
	if err != nil {
		log.Fatalf("load keys error:\n%v\n", err)
	}

	// add server cert to root CA pool
	err = client.AddCertToRootCA([]byte(srvCertPem))
	if err != nil {
		log.Fatalf("load server cert error:\n%v\n", err)
	}

	conn, err := client.Dial()
	if err != nil {
		log.Fatalf("fail to dial with server:\n%v\n", err)
	}
	defer conn.Close()

	messageCount := 3

	for i := 0; i < messageCount; i++ {
		message := "Hello server! Message " + strconv.Itoa(i+1)

		n, err := io.WriteString(conn, string(message))
		if err != nil {
			log.Fatalf("client: write: %s", err)
		}

		log.Printf("client: wrote %q (%d bytes)", message, n)

		reply := make([]byte, 256)

		n, err = conn.Read(reply)
		if err != nil {
			log.Fatalf("client: write: %s", err)
		}

		log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	}

	log.Println("client: exiting")
}

const srvCertPem = `-----BEGIN CERTIFICATE-----
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

const certPem = `-----BEGIN CERTIFICATE-----
MIID7TCCAtegAwIBAgICBnYwCwYJKoZIhvcNAQELMGIxETAPBgNVBAYTCFNoYW1i
YWxhMQwwCgYDVQQKEwNaRU4xDTALBgNVBAsTBE9tIDAxCzAJBgNVBAcTAlVBMQ8w
DQYDVQQIEwZzaGFtIDAxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNDEyMjkxNDU0
MTBaFw0yNDEyMjkxNDU0MTBaMGIxETAPBgNVBAYTCFNoYW1iYWxhMQwwCgYDVQQK
EwNaRU4xDTALBgNVBAsTBE9tIDAxCzAJBgNVBAcTAlVBMQ8wDQYDVQQIEwZzaGFt
IDAxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKdrR7ZczRslfVzNTqu/S2my3MSlHRrqyPZHOGKxU42lqX4PtUM8Neoz
/O5ZJv0luCVJ+rRc3gX4zyZDM3eTaIW//bZyc2G2SEM6HkpEvLg8sE2KhYT6CDq2
QKS0DECjLa39ODmSu5RlDCMW09Yp/V4gEZv400y0WSBgjJ4c5RdyRxPPqrhhC4da
/1R00qoZzw3tqFMikiUOV0F++RpEdDL4vNMMf9C9Mw0WOkkMW5Z+kMq0PYjoBtbZ
EnUteaIXO5FF4GYIjWlnX7KWPs2D8JlITAotqXOYsCzsFPhPbkDIJGqU4gyyAr/k
riFQZb58Lpkx3A7PzXLH6yXDdMvEpFUCAwEAAaOBsDCBrTAOBgNVHQ8BAf8EBAMC
AIQwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFB952/YI+PbjSZFBw0BaTvQsvO5TMB8GA1UdIwQYMBaAFLbP
qUht4U+mq/1jkykMq2B0h9xXMCsGA1UdEQQkMCKCCWxvY2FsaG9zdIIJbG9jYWxo
b3N0hwR/AAABhwR/AAABMAsGCSqGSIb3DQEBCwOCAQEAL7tlUrmZF+umN8YbU83H
fvjjADk/vWQZf5s9ngbGv8yicl32blKIYjAcVd1XdUk2bexFK7VBB9jhj44wnl++
0WJ8lSEGLRUOkx54EoZ+XGZJs2xlNauVTYBCPzKP45q37V5tDSZg1lcrzZw1xZzq
3jxLYOpx9JRPlKDYqMW9ce0d+nWWJL2LrnKOavmK7MSbYpdmH5WWUNrV/zTOcCFh
0eT+I1z52oIxV3/oWZSSXNN777b6D6KuvzU+QxFd2AfATiwbPS3yfPqnjMxQA818
kg13wzrIQ1qARG2zJ6zDgWPScWxOhYN0b662Ub8lLnYfVEI5g9sSgbusZ3Gy8m6e
rg==
-----END CERTIFICATE-----`

const pkey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp2tHtlzNGyV9XM1Oq79LabLcxKUdGurI9kc4YrFTjaWpfg+1
Qzw16jP87lkm/SW4JUn6tFzeBfjPJkMzd5Nohb/9tnJzYbZIQzoeSkS8uDywTYqF
hPoIOrZApLQMQKMtrf04OZK7lGUMIxbT1in9XiARm/jTTLRZIGCMnhzlF3JHE8+q
uGELh1r/VHTSqhnPDe2oUyKSJQ5XQX75GkR0Mvi80wx/0L0zDRY6SQxbln6QyrQ9
iOgG1tkSdS15ohc7kUXgZgiNaWdfspY+zYPwmUhMCi2pc5iwLOwU+E9uQMgkapTi
DLICv+SuIVBlvnwumTHcDs/NcsfrJcN0y8SkVQIDAQABAoIBAG7x8vXwjaNdtrPX
AjlibXFALHjMCnuZ907tZ3pPlNUbYTS+6BoEPp5TkVvKDMJZSqy7V75KhH9koLH0
epjVQMDRuCo9siSgjUavrv78iit1XEgmcdDreKSfvjrnbe8vs8fHNIlCqbfvNpnS
ONOFw/eqPMElpbEBGscP9F+bOl3MNNY5yIHABDOM2agA1AwmGZJt3evQnBvgUaKB
TMa/YoaNiKzB5uBs6Ji+mpgnhpeqMZt8PDqMLkrBXM4ULH9+eUopD22anrDeAQjk
0HmV9CIcRSUTu0d0JJtjZMgj/VsIDueE0ceVNgK0wHsRuqrWx4/h8niXE1bl96RP
MHAUr8ECgYEAzgETYbM1FGROT64MsD66G/2ZMU647qRQLghW9VH2TGTstb8PUuo+
3KC9LvZsIRf6GlUe5mjV7tnGGYd4MWsrACWq9aValnpa8TkHd0XhLMK6TFM9ytig
7DN6o9vH4b40V2jbK5o3UWx4sDuSsLnlAjuJD4gXBpo/f4t7LTrrnh0CgYEA0Azu
fZouxX7hXazsXExPCAZM/RKjkhluuqMETE8Bpgry9PHbLYX0New6j8HCyiko6bkc
t1HRdgNG9v+ZI10jJBwM4m/7pCFZNuVSmY/ToeWeZuJ+FEYpGjzmeJmqhK0UmNGm
s3ZREVw5Sq5IsLAf/rz6HjKoD2tqzY56AGM6qZkCgYEAzbShR/QNUtl+oW4pWWyp
pv2rFWOIozQMpIrLWpiHm21EOZAZmzAxqVoQz25eNwWcRuMsweN5jNKFUETILoDX
JYR3nGeLd6uiWDIcVGvBGFMyeLi+gWmj93jIRAtZIwAtgANCp92M04+/TCuQpUxb
c8lDafD5HSy1r4T2cQne8bkCgYBkAGM+Ejc7DMKssSqnLrKqK8Uju6rN1dWodiTh
vPQQ6KBhZkMwvXtl09dONBc57tDQjv6jivtAW1Dn9nGYUvNKLwVubd8pxDHKti2e
zEgwQFuEHof1nMey6eTpwQr6XOtSjSswhcVvr8GGCQG9k9q9Kf6bN0QarUoX5cz0
lL2kuQKBgGmWlhpQTpfXvM65W1sol4f87k6fnAoc+ifY/AWCOV9P4xo3scEDzEkf
+wGcuym+rR59443SoZIYt429BrTKFVkbEiC3I6fcUK/fHoyj8TgT1SxgON5nL6o5
6/7HAC+Op9sr19aHz3vHhOww2wKrb/W42kqUcBbVUYCBPIPyR8Wt
-----END RSA PRIVATE KEY-----`
