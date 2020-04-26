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
    "github.com/gorilla/websocket"
    "net/http"
    "log"
    "html/template"
    "bytes"
    "encoding/json"

)
var (
    key, _ = ecdsa.GenerateKey(curve, rand.Reader)
    ServerPts = []string{"02384234", "09asoasdfj32", "hello","data", "world","other","random"}
    curve = elliptic.P256()
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
    
    x = new(big.Int).SetBytes(r)
    x3 := new(big.Int).Mul(x, x)
    x3.Mul(x3, x)
    threeX := new(big.Int).Lsh(x, 1)
    threeX.Add(threeX, x)

    x3.Sub(x3, threeX)
    x3.Add(x3, curve.Params().B)
    // fmt.Println("x3 val:",fmt.Sprintf("%x",x3))
    // fmt.Println("B val:",fmt.Sprintf("%x",c.Params().B))
    // fmt.Println("P val:",fmt.Sprintf("%x",c.Params().P))
    y = x3.ModSqrt(x3, curve.Params().P)
    // fmt.Println("x val:",fmt.Sprintf("%x",x))
    // fmt.Println("y val:",fmt.Sprintf("%x",y))
    return
}

func increment(counter []byte) {
    for i := len(counter) - 1; i >= 0; i-- {
        fmt.Println("set counter=",i, " with length=", len(counter))
        counter[i]++
        if counter[i] != 0 {
            break
        }
    }
}

func readBit(buffer []byte, bytePos int, bitPos int) int{
    return int((buffer[bytePos] >> bitPos) % 2)
}

func setBit(buffer []byte, bytePos int, bitPos int, value int){
    fmt.Println("SET BIT VALUE BEFORE=",readBit(buffer,bytePos,bitPos))

    if value == 0{
        buffer[bytePos] &= ^(1 << bitPos);
    }else{
        fmt.Println("set value to 1")
        buffer[bytePos] |= (1 << bitPos);
        
    }
    fmt.Println("SET BIT VALUE AFTER=",readBit(buffer,bytePos,bitPos))

}

func incrementLSB(buffer []byte){
    for i:=len(buffer)-1 ; i>=0; i--{
        for b:=0; b<8; b++{
            fmt.Println("iter:",(i+1)*8-(b+1) , " value:", readBit(buffer,i,b))
            if(readBit(buffer,i,b)==0){
                setBit(buffer,i,b,1);
                fmt.Println("set bit:",(i+1)*8-(b+1));
                return;
            }
        }        
    }
}

func HashIntoCurvePoint(c elliptic.Curve, r []byte) (x, y *big.Int) {
    t := make([]byte, 32)
    copy(t, r)

    x, y = tryPoint(t)
    for y == nil || !c.IsOnCurve(x, y) {
        fmt.Println("point not on curve, try again")
        incrementLSB(t)
        x, y = tryPoint(t)

    }
    return x,y
}

func EncryptValueToDer(key *ecdsa.PrivateKey,c elliptic.Curve,r string)string{
    hash := sha256.Sum256([]byte(r))
    fmt.Println("hash value:",hex.EncodeToString(hash[:]))
    x, y := HashIntoCurvePoint(c, hash[:]) // Convert password hash into elliptic curve point.
    fmt.Println("CURVE X value:",hex.EncodeToString(x.Bytes()))
    fmt.Println("CURVE Y value:",hex.EncodeToString(y.Bytes()))
    x,y = c.ScalarMult(x,y,key.D.Bytes())
    fmt.Println("X value:",hex.EncodeToString(x.Bytes()))
    fmt.Println("Y value:",hex.EncodeToString(y.Bytes()))
    return EncodePoint(c, x,y)

}

func EncodePoint(c elliptic.Curve, x,y *big.Int) string{
    return hex.EncodeToString(eccp.Marshal(c, x, y))
}

func DecodePoint(derPoint []byte) (x,y *big.Int){
    parsed,err := hex.DecodeString(string(derPoint[:]))
    if err!=nil {
        fmt.Printf("error decoding der point:%s\r\n", derPoint)
        return
    }
    x,y = eccp.Unmarshal(curve,parsed)
    return
}

var addr = flag.String("addr", "localhost:8080", "http service address")

var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
} // use default options

func StreamECDH(w http.ResponseWriter, r *http.Request) {
    upgrader.CheckOrigin = func(r *http.Request) bool { return true }
    c, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        fmt.Print("upgrade:", err)
        return
    }
    defer c.Close()
    for {
        messageType, message, err := c.ReadMessage()
        message = bytes.TrimSpace(message)
        if err != nil {
            fmt.Println("read:", err)
            break
        }
        fmt.Printf("recv: %s", message)
        x,y := DecodePoint(message)
        fmt.Println("X value:",hex.EncodeToString(x.Bytes()))
        fmt.Println("Y value:",hex.EncodeToString(y.Bytes()))
        x,y= curve.ScalarMult(x,y,key.D.Bytes())
        EncodePoint(curve, x,y)
        err = c.WriteMessage(messageType, message)
        if err != nil {
            fmt.Println("write:", err)
            break
        }
    }
}

type ClientEcdh struct {
    ClientDerPts []string
}

type ServerEcdh struct{
    ClientDerPts []string
    ServerDerPts []string
}


//TODO:FOR TESTING ONLY
func enableCors(w *http.ResponseWriter) {
    (*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func ECDH(rw http.ResponseWriter, req *http.Request) {
    decoder := json.NewDecoder(req.Body)
    //fmt.Println(decoder)
    var pts ClientEcdh
    err := decoder.Decode(&pts)
    if err != nil {
        panic(err)
    }

    result := ServerEcdh{
        ClientDerPts:[]string{},
        ServerDerPts:[]string{},
    }

    fmt.Println(pts.ClientDerPts)
    for i, derPoint := range pts.ClientDerPts {
        x,y := DecodePoint([]byte(derPoint))
        fmt.Println("X value:",hex.EncodeToString(x.Bytes()))
        fmt.Println("Y value:",hex.EncodeToString(y.Bytes()))
        fmt.Println(i, derPoint)
        x,y= curve.ScalarMult(x,y,key.D.Bytes())
        cpp := EncodePoint(curve, x,y)
        result.ClientDerPts = append(result.ClientDerPts,cpp)
    }

    fmt.Println("SERVER VALUES-------------------------------------")

    for i, srvPts := range ServerPts{
        spp:= EncryptValueToDer(key, curve, srvPts)
        fmt.Println(i, spp)
        result.ServerDerPts = append(result.ServerDerPts,spp )
    }
    
    rw.Header().Set("Content-Type", "application/json")
    json.NewEncoder(rw).Encode(result)

}

func Home(w http.ResponseWriter, r *http.Request) {
    homeTemplate.Execute(w, "ws://"+r.Host+"/echo")
}

func main() {

    flag.Parse()
   
   

  //  // args := flag.Args()
  //   pwd:="GEOHASHINGVALUE"

  // //  if (args.len>1) { pwd=args[0] }

  //   hash := sha256.Sum256([]byte(pwd))
  //   fmt.Println("hash:", fmt.Sprintf("%x",hash))
  //   x, y := HashIntoCurvePoint(curve, hash[:]) // Convert password hash into elliptic curve point.
  //   fmt.Println("Password:           ", pwd)
  //   x,y = curve.ScalarMult(x,y,key.D.Bytes())
  //   fmt.Println("DER value:",hex.EncodeToString(eccp.Marshal(curve, x, y)))    
  //   fmt.Println("DER value:",EncryptValueToDer(key,curve,pwd))

    log.SetFlags(0)
    fs := http.FileServer(http.Dir("../dist"))
    http.Handle("/", fs)
    http.HandleFunc("/stream", StreamECDH)
    //http.HandleFunc("/", Home)
    http.HandleFunc("/ecdh",ECDH)
    log.Fatal(http.ListenAndServe(*addr, nil))


}



var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>  
window.addEventListener("load", function(evt) {
    var output = document.getElementById("output");
    var input = document.getElementById("input");
    var ws;
    var print = function(message) {
        var d = document.createElement("div");
        d.textContent = message;
        output.appendChild(d);
    };
    document.getElementById("open").onclick = function(evt) {
        if (ws) {
            return false;
        }
        ws = new WebSocket("{{.}}");
        ws.onopen = function(evt) {
            print("OPEN");
        }
        ws.onclose = function(evt) {
            print("CLOSE");
            ws = null;
        }
        ws.onmessage = function(evt) {
            print("RESPONSE: " + evt.data);
        }
        ws.onerror = function(evt) {
            print("ERROR: " + evt.data);
        }
        return false;
    };
    document.getElementById("send").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        print("SEND: " + input.value);
        ws.send(input.value);
        return false;
    };
    document.getElementById("close").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        ws.close();
        return false;
    };
});
</script>
</head>
<body>
<table>
<tr><td valign="top" width="50%">
<p>Click "Open" to create a connection to the server, 
"Send" to send a message to the server and "Close" to close the connection. 
You can change the message and send multiple times.
<p>
<form>
<button id="open">Open</button>
<button id="close">Close</button>
<p><input id="input" type="text" value="Hello world!">
<button id="send">Send</button>
</form>
</td><td valign="top" width="50%">
<div id="output"></div>
</td></tr></table>
</body>
</html>
`))