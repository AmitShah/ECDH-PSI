var EC = require('elliptic').ec;
var BN = require('bn.js');
const curve = new EC("p256");
const sha256 =curve.hash(); 
const red = BN.red(curve.curve.p);

function _tryPointNotReductionContext(r){
    var x = new BN(r,16);
    var result = (x.pow(new BN(3)).sub(x.mul(new BN(3))).add(curve.curve.b.fromRed())).toRed(red).redSqrt().fromRed()
    return result;
}

function _pointFromX(x,odd) {
  //BN simply returns the passed in value if it is a BN, however; 
  //reduction contexts are immutable, so we have to do some craziness
  var a = new BN(curve.curve.a.fromRed().toString(16), 16).toRed(red);
  var b = new BN(curve.curve.b.fromRed().toString(16), 16).toRed(red);
  console.log("a:",a.fromRed().toString(16))
  console.log("b:",b.fromRed().toString(16))
  x = (new BN(x, 16)).toRed(red);
  if(!x.red){
    console.log("NOT REDUCTION CONTEXT");
    x = x.toRed(red);
  }

  var y2 = x.redSqr().redMul(x).redIAdd(x.redMul(a)).redIAdd(b);
  var y = y2.redSqrt();
  if (y.redSqr().redSub(y2).cmp(curve.curve.zero) !== 0)
    throw new Error('invalid point');
  
  var isOdd = y.fromRed().isOdd();
  if (odd && !isOdd || !odd && isOdd)
    y = y.redNeg();
  console.log("pontFromX:",y.fromRed().toString(16));
  return  curve.curve.point(x,y);
};


function readBit(buffer, i, bit){
  return (buffer[i] >> bit) % 2;
}

function setBit(buffer, i, bit, value){
  if(value == 0){
    buffer[i] &= ~(1 << bit);
  }else{
    buffer[i] |= (1 << bit);
  }
}

//increment the least signficant bit 
function incrementLSB(buffer){
    for(var i=(buffer.length)-1 ; i>=0; i--){
        for(var b=0; b<8; b++){
            console.debug("iter:",(i+1)*8-(b+1) , " value:", readBit(buffer,i,b));
            if(readBit(buffer,i,b)===0){
                setBit(buffer,i,b);
                console.debug("set bit:",(i+1)*8-(b+1));
                return;
            }
        }        
    }
    throw new Error("no bits left to increment");
}

function tryPoint(r){
    for(;;){
        try{
            return curve.curve.pointFromX(r);
            //return pointFromX(r) no need for custom
        }catch(e){
            //console.error(e);
            //if we cannot encode point we throw a final error to break the for loop
            incrementLSB(r);
            
        }
    }
}

function encryptValueToDER(secret,value){
  console.log("hash value=",curve.hash().update(value).digest("hex"));
  value = curve.hash().update(value).digest();
  value = tryPoint(value);
  console.debug("curve x:",value.getX().toString(16));
  console.debug("curve y:",value.getY().toString(16));
  value = value.mul(secret);
  console.debug("x:",value.getX().toString(16));
  console.debug("y:",value.getY().toString(16));
  return value.encodeCompressed('hex');
}

function decodeDerPoint(derPoint){
  var value =  curve.curve.decodePoint(derPoint,'hex');
  console.debug("x:",value.getX().toString(16));
  console.debug("y:",value.getY().toString(16));
  return value;
}

// End Cryptographic Functions

var AliceValues = ["hello","world"];

var Xhr = require('xhr-request')

function processEcdh(){
  var EphemerealKey = curve.genKeyPair();
  var pts = AliceValues.map(v=>{
    return encryptValueToDER(EphemerealKey.getPrivate(),v); 
  });
  pts.forEach(p=>{
    console.log("timestamp=", Date.now(), " derPoint=" ,p);
  })

  Xhr('http://localhost:8080/ecdh', {
    method: 'POST',
    json: true,
    body: { ClientDerPts: pts },
    responseType: 'json'
  }, function (err, data) {

    if (err) throw err
    console.log('got Server Results: ', data)

    var serverPts = data.ServerDerPts.map(sdp=>{
      var pt = decodeDerPoint(sdp);
      pt = pt.mul(EphemerealKey.getPrivate());
      return pt.encodeCompressed('hex')
    });

    console.log("CLIENT POINTS:", data.ClientDerPts);
    console.log("SERVER POINTS:", serverPts);

  })
  //sendToServer();


};


//TODO add stream processing support
function streamProcess(){

  var client = new WebSocket('ws://localhost:8080/StreaECDH');

  var EphemerealKey = curve.genKeyPair();
  var serverPoints = [];
  var clientPoints = [];

  client.onerror = function(e) {
    //client.close();
    console.log(e);
    console.log('Connection Error');
  };

  client.onopen = function() {
    console.log('Generating Ephemereal Key');
    //Generate Ephemereal Key
    
    
    function sendEncryptedPoints() {
      if (client.readyState === client.OPEN) {
        AliceValues.forEach(v=>{
          var derPoint = encryptValueToDER(EphemerealKey.getPrivate(),v); 
          console.log("send value:",derPoint);
          client.send(derPoint);
        });
      }
    }

    sendEncryptedPoints();
  };

  client.onclose = function() {
    console.log('echo-protocol Client Closed');
  };

  client.onmessage = function(message) {
    console.log("Received: '" + JSON.stringify(message) + "'");
    if(message.type==='ServerPoint'){
      var sp = curve.curve.decodePoint(message.value, 'hex');
      sp = sp.mul(EphemerealKey.getPrivate()).encodeCompressed('hex');
      serverPoints.push(sp);
    }else if(message.type==='ClientPoint'){
        //push derPoint
        clientPoints.push(msg.value);
      }else if(message.type=='CompletedProcessing'){
        client.close();
        console.log('compre points');
      }

    };

    return client;
}

processEcdh();
//streamProcess();







