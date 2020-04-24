// https://asecuritysite.com/encryption/goecch
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
     "encoding/hex"
    "math/big"
        "flag"
    "github.com/fd/eccp"

)
var (
    c = elliptic.P256()
    k = new(big.Int).SetBytes([]byte{164, 98, 192, 51, 205, 206, 226, 85, 22, 79, 248, 231, 248, 171, 160, 1, 248, 166, 173, 240, 47, 68, 92, 163, 33, 118, 150, 220, 69, 51, 98})

)
var one = new(big.Int).SetInt64(1)

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
    // Inverse returns the inverse of k in GF(P)
    Inverse(k *big.Int) *big.Int
}

func randScalar(c elliptic.Curve) (k *big.Int, err error) {
    params := c.Params()
    k, err = rand.Int(rand.Reader, params.N)
    return
}

func fermatInverse(k, N *big.Int) *big.Int {
    two := big.NewInt(2)
    nMinus2 := new(big.Int).Sub(N, two)
    return new(big.Int).Exp(k, nMinus2, N)
}

func tryPoint(r []byte) (x, y *big.Int) {
    //hash := sha256.Sum256(r)
    x = new(big.Int).SetBytes(r)

    x3 := new(big.Int).Mul(x, x)
    x3.Mul(x3, x)

    threeX := new(big.Int).Lsh(x, 1)
    threeX.Add(threeX, x)

    x3.Sub(x3, threeX)
    x3.Add(x3, c.Params().B)
    fmt.Println("x3 val:",fmt.Sprintf("%x",x3))
    fmt.Println("B val:",fmt.Sprintf("%x",c.Params().B))
    fmt.Println("P val:",fmt.Sprintf("%x",c.Params().P))
    y = x3.ModSqrt(x3, c.Params().P)

    fmt.Println("x val:",fmt.Sprintf("%x",x))
    fmt.Println("y val:",fmt.Sprintf("%x",y))
    return
}

func increment(counter []byte) {
    for i := len(counter) - 1; i >= 0; i-- {
        counter[i]++
        if counter[i] != 0 {
            break
        }
    }
}

func HashIntoCurvePoint(c elliptic.Curve, r []byte) (x, y *big.Int) {
    t := make([]byte, 32)
    copy(t, r)

    x, y = tryPoint(t)
    for y == nil || !c.IsOnCurve(x, y) {
        increment(t)
        x, y = tryPoint(t)

    }
    return x,y
}
func main() {



    flag.Parse()
    curve:=elliptic.P256()

    key, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        return
    }
    

   // args := flag.Args()
    pwd:="GEOHASHINGVALUE"

  //  if (args.len>1) { pwd=args[0] }

    hash := sha256.Sum256([]byte(pwd))
    fmt.Println("hash:", fmt.Sprintf("%x",hash))
    x, y := HashIntoCurvePoint(curve, hash[:]) // Convert password hash into elliptic curve point.
    fmt.Println("Password:           ", pwd)
    x,y = curve.ScalarMult(x,y,key.D.Bytes())
    fmt.Println("DER value:",hex.EncodeToString(eccp.Marshal(curve, x, y)))    
    // fmt.Println("\nHash to point:\t", pkx, pky)

    // r, _ := randScalar(c) // Random value to mask password

    // x, y := c.ScalarMult(pkx, pky, r.Bytes()) // Calculate point on elliptic curve

    // fmt.Println("\nRandom value:\t", r)

    // fmt.Println("\nMasked:\t", x, y)
    // rInv := fermatInverse(r, c.Params().N) // rInv = r ^-1

    // x1, y1 := c.ScalarMult(x, y, rInv.Bytes()) 

    // fmt.Println("\nUnmasked:\t", x1, y1)



}