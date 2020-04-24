package main

import (
  "fmt"
  "crypto/elliptic"
  "encoding/hex"
  "crypto/rand"
  "github.com/fd/eccp"
)

func main() {
  priv,x,y,_ := elliptic.GenerateKey(elliptic.P256(),rand.Reader)
  //DER encode point
  marshalled := eccp.Marshal(elliptic.P256(),x,y)
  hexM := hex.EncodeToString(marshalled)
  fmt.Println(priv)
  fmt.Println(hex.EncodeToString(x.Bytes()))
  fmt.Println(hex.EncodeToString(y.Bytes()))
  fmt.Println(hexM)
  testHex := "022a808f2449a3eb00904b88dbdfdf64cd4ccbfad76eb35385d7135ad94cdabb27"
  fmt.Println(testHex)
  //parsed,_ := hex.DecodeString(hexM)
  parsed,_ := hex.DecodeString(testHex)
  //DER decode point
  x2,y2 := eccp.Unmarshal(elliptic.P256(),parsed)
  fmt.Println("X value:",hex.EncodeToString(x2.Bytes()))
  fmt.Println("Y value:",hex.EncodeToString(y2.Bytes()))

  fmt.Println("DER value:",hex.EncodeToString(eccp.Marshal(elliptic.P256(), x2, y2)))
  if x.Cmp(x2)==0 && y.Cmp(y2)==0{
    fmt.Println("all good")
  }else{
    fmt.Println("all bad")
  }
  
  //h^(xa)b
  elliptic.P256().ScalarMult(x2, y2, priv)
}


