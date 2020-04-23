package psi

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "github.com/awnumar/memguard"
 "fmt"
)

type Secure struct {
	PrivKey       [32]byte
	
}

func GenerateKey(){

	s := new(ecdsa.PrivateKey)

	// Allocate a LockedBuffer of the correct size
	b := memguard.NewBuffer(int(unsafe.Sizeof(*s)))

	// Return the LockedBuffer along with the initialised struct
	return b, (*Secure)(unsafe.Pointer(&b.Bytes()[0]))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err!=nil{
		return
	}



}

func GenerateKeyEnclave(){
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enclave:= memguard.NewEnclave(priv)
}

func DiffieHellman(){

}