package main

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"code.google.com/p/go.crypto/ssh"
)

// Add your private key - either hard code it or read from a file, etc.
// NOTE: This cannot be protected by a passphrase -- it won't work.
// It requires additional code to that passphrase'd keys work -- use the openpgp module.
const clientPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA81CcejS/KQz7GF4bGxXbiXQoYV8aNIsFPp+hJkMGL2Uf+Oxd
YBSwSuuyGGYXYqA42O3qmuRCZysTvvMyp82LK5tzpb98FuNctdvOVPh09wXMScZu
S8Gi/8XNFf61fqVujBgcTWJAsyUBs5RUgQSf01HxH9NviOt8l+o+ulPxrsDrqd/9
E7dmRdljEmAW3RxchIQ45jTXzPsqClN2IVJ8Ss53UfkMpEWIwatZYTj4z6hUKXDb
uIGvo8nuOJG+36XOWfnyl18zgTqLPnMnwioLMKoK4KtnI3vUjqRNcPKQUIE0oi4Q
q1GiMJKLARokyE913laHbD4KtBBmT+HzddDlcwIDAQABAoIBAQC671D5NvMzJ8z2
gL6UhauApGStwrJQcgqafWwDCHWFDk2NIpPu0JZNSV4wDqei13Q1fjzDueEmgFsQ
Vqqxb2KgIzOrwT0mHJJLClAwyh6a9rJob/Knc2K23ZJedq2cWp9fNNrxvS32NNVk
0e5GnXXplkgJ6pkDeeDkmkyNPRcu6Xvkk7W/gW1sFSnmuh15GNRbRXXR718fr7L7
pSJKV4nvpPjYXdr2ka11oUmndeG5dmslY2oUOmUFav/siXOGLyY1LYdjrEAKxW4Q
4Kfzxhvsy6kRFgp+H+YspgABnDlJacjJwGCtSExA3XDaNbXOzmzeJ98ima6DuUg/
i95ONo35AoGBAPsSI1KIXUNRhmg/judXgG4KNPYHncVA31oY5fqtZiQios5+pPgl
zXoxFtZqvXfUCXDjy+T55ClUAJb3ASPmkvb53WyAZKYSprwyIYYy9yWidH+Fbbks
HfdYhLN1gwAsHQRWHoZQkXqITVMAqZ7MiOBmXWQFv/I3Qv3omMK/UZKdAoGBAPgX
fg5t+A+DtXU0Dz0Up5KDJaaYn72raJZGbTFYu7ONL6C5d1FV9YMV2zucZVxZRI6O
6/LWKdcSX351Xz8gdAafS6MewSRUOmRSZGiGyLJ77uS9ZeYJAdjGbjOZ9+tte6bX
EecIcin64bxMFL3JRvWPIjAAgJTP4YloFWMT3xNPAoGAIz64lq1t6jVXmOrTNMaj
0M6+AIuxKi+hKxSztC0DWa9DC5nbrrofzjd17UOutVOev6o6xToPPX39VzP1hQSp
POJ2ovSjLG0R2vlum1gsOaxEjmI8tPHsgvx6JHcqnKuUpzcvscs9oOXhdPVy2kf8
LwQvuArWlzoKvXoZd71DxkECgYBnEnuQyydwaqwNEZ/zJI2qVUpjOK3FQ12kcYYU
JmV1Z4cOI3/rDud9mqsGzSdfgsb043Qr48ZmUH/ULjdwJq+NwMjP8IsV6NiJraGB
u93OKadK6VVYiQ13XpmSXrmd2lKxMlGBxwSHZHA8pu9HGkSc6OavQsYpDWUKjW+1
RiA8CQKBgQDO2ky8uMNYcPTqm+TMQjS46ZeX29s/gPDcS1b3w+yECKo50iqGdDac
aYqC/0AUsf4tW33M/dmF5yRO4BDpeBcXU7twU0nX5RoHW3kaBrsz9tpELCf3/5c/
DZJwDeel1QicGW1t+IpgJcAmfYNY0yUWvMdUwk2eHlAxgiIIOSSz2g==
-----END RSA PRIVATE KEY-----`

// keychain implements the ClientKeyring interface
type keychain struct {
	keys []interface{}
}

// Implements the interface.
// Taken from https://code.google.com/p/go/source/browse/ssh/client_auth_test.go?repo=crypto
func (k *keychain) Key(i int) (interface{}, error) {
	if i < 0 || i >= len(k.keys) {
		return nil, nil
	}
	switch key := k.keys[i].(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *dsa.PrivateKey:
		return &key.PublicKey, nil
	}
	panic("unknown key type")
}
func (k *keychain) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	switch key := k.keys[i].(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand, key, hashFunc, digest)
	}
	return nil, errors.New("ssh: unknown key type")
}

func main() {
	// Decode and parse our key
	block, _ := pem.Decode([]byte(clientPrivateKey))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// Add it to the keychain
	clientKeychain := new(keychain)
	clientKeychain.keys = append(clientKeychain.keys, privateKey)

	// Create our client config with key-based auth
	config := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(clientKeychain),
		},
	}

	// Connect
	client, err := ssh.Dial("tcp", "127.0.0.1:22", config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}

	// Create a new session
	session, err := client.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	// Execute command
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/bin/whoami"); err != nil {
		panic("Failed to run: " + err.Error())
	}
	fmt.Print(b.String())
}
