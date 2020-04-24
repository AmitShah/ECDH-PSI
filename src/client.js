var EC = require('elliptic').ec;
var hash = require('hash.js');
var curves = require('elliptic').curves;
//var ec = new EC('curve25519');
var ec = new EC("p256");
var BN = require('bn.js');


// Generate keys
var key1 = ec.genKeyPair();
var key2 = ec.genKeyPair();

var shared1 = key1.derive(key2.getPublic());
var shared2 = key2.derive(key1.getPublic());

console.log('Both shared secrets are BN instances');
console.log(shared1.toString(16));
console.log(shared2.toString(16));



var A = ec.genKeyPair();
var B = ec.genKeyPair();
var C = ec.genKeyPair();

var AB = A.getPublic().mul(B.getPrivate())
var BC = B.getPublic().mul(C.getPrivate())
var CA = C.getPublic().mul(A.getPrivate())

var ABC = AB.mul(C.getPrivate())
var BCA = BC.mul(A.getPrivate())
var CAB = CA.mul(B.getPrivate())

console.log(ABC.getX().toString(16))
console.log(BCA.getX().toString(16))
console.log(CAB.getX().toString(16))


/*
The Decisional Diffie-Hellman assumption
– Agree on a group G, with a generator g.
– The assumption: for random a,b,c
cannot distinguish (g
a
, g
b
, gab) from (g
a
, g
b
, g
c
)
*/

var value =  new BN('dead', 16);

var serverValue = new BN('dead',16);


console.log("\r\n TESTING DH PSI");

//in this case, A.getPublic() must also remain secret

var clientValue = A.ec.g.mul(A.getPrivate().mul(value));

console.log("X value:",clientValue.x.fromRed().toString(16));
console.log("Y vakye:",clientValue.y.fromRed().toString(16));
console.log("DER VALUE:",clientValue.encode("hex",true));



//This direct hasihing to EC point is not secure scheme if we want to do other things on this point. i.e. we cannot run BLS signatures
//more so, we can basically find out what the secret key is if we ever use the same key twice

//re: broken security of direct hashing https://www.normalesup.org/~tibouchi/papers/bnhash-scis.pdf

//https://medium.com/@billatnapier/matching-a-value-to-an-elliptic-curve-point-6a6f29e18482
//Koblitz's try and incremenet approach (there exists faster approaches)
//https://asecuritysite.com/encryption/hash_to_ecc?a0=10&a1=37

// var serverValue= B.ec.g.mul(B.getPrivate().mul(serverValue));

// var clientServerValue = clientValue.mul(B.getPrivate());

// console.log(clientValue.getX().toString(16));

// console.log(serverValue.getX().toString(16));

// console.log(clientServerValue.getX().toString(16));

// var compareValue = serverValue.mul(A.getPrivate());

// console.log(compareValue.getX().toString(16));

console.log("-----------------------------------\r\n");
var Alice = ec.genKeyPair();

value= "GEOHASHINGVALUE";
curve = new EC("p256");
r = curve.hash().update(value).digest();//"hex");
var red = BN.red(curve.curve.p);
x = new BN(r,16);
console.log("hash:",r.toString('hex'));
var result = x.pow(new BN(3)).sub(x.mul(new BN(3))).add(curve.curve.b.fromRed())
var resultR = result.toRed(red);

console.log("A val:",curve.curve.a.fromRed().toString('hex'));
console.log("B val:",curve.curve.b.fromRed().toString('hex'));
console.log("P val:",curve.curve.p.toString('hex'));
console.log("x3 value:",result.toString(16));
console.log("y value:", resultR.redSqrt().toString(16));


const CURVE = new EC("p256");
const RED = BN.red(CURVE.curve.p);

function tryPointNotReductionContext(r){
    var x = new BN(r,16);
    var result = (x.pow(new BN(3)).sub(x.mul(new BN(3))).add(CURVE.curve.b.fromRed())).toRed(red).redSqrt().fromRed()
    return result;
}


function pointFromX(x,odd) {
  //BN simply returns the passed in value if it is a BN, however; 
  //reduction contexts are immutable, so we have to do some craziness
  var a = new BN(CURVE.curve.a.fromRed().toString(16), 16).toRed(RED);
  var b = new BN(CURVE.curve.b.fromRed().toString(16), 16).toRed(RED);
  console.log("a:",a.fromRed().toString(16))
  console.log("b:",b.fromRed().toString(16))
  x = (new BN(x, 16)).toRed(RED);
  if(!x.red){
    console.log("NOT REDUCTION CONTEXT");
    x = x.toRed(RED);
  }

  var y2 = x.redSqr().redMul(x).redIAdd(x.redMul(a)).redIAdd(b);
  var y = y2.redSqrt();
  if (y.redSqr().redSub(y2).cmp(CURVE.curve.zero) !== 0)
    throw new Error('invalid point');
  
  var isOdd = y.fromRed().isOdd();
  if (odd && !isOdd || !odd && isOdd)
    y = y.redNeg();
  console.log("pontFromX:",y.fromRed().toString(16));
  return  CURVE.curve.point(x,y);
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
            //console.debug("iter:",(i+1)*8-(b+1) , " value:", readBit(buffer,i,b));
            if(readBit(buffer,i,b)===0){
                setBit(buffer,i,b);
                console.debug("set bit:",(i+1)*8-(b+1));
                return;
            }
        }        
    }
}



function tryPoint(r){
    for(;;){
        try{
            return CURVE.curve.pointFromX(r);
            //return pointFromX(r) no need for custom
        }catch(e){
            console.error(e);
            incrementLSB(r);
            
        }
    }
}



var p = tryPoint(r);
console.log("bult-in x:",p.x.fromRed().toString(16));
console.log("bult-in y:",p.y.fromRed().toString(16));
console.log(Buffer.from(r).toString('hex'))

//console.log("custom:",tryPoint(r).y.fromRed().toString(16));


console.log("DER point:",p.encode("hex",true));

function BytesToPoint(v){
    
    // // Import x into bigInt library
    // var x3 = new new BN(v);
    // x3.pow(3).sub(v.mul(3));

    // x3.add(v)

    // x^3 

    // x3 := new(big.Int).Mul(x, x)
    // x3.Mul(x3, x)

    // threeX := new(big.Int).Lsh(x, 1)
    // threeX.Add(threeX, x)

    // x3.Sub(x3, threeX)
    // x3.Add(x3, c.Params().B)

    // y = x3.ModSqrt(x3, c.Params().P)
    // return
    // // y^2 = x^3 - 3x + b
    // var yBig = xBig.pow(3).sub( xBig.multiply(3) ).add( b ).modPow( pIdent, prime );

    // // If the parity doesn't match it's the *other* root
    // if( yBig.mod(2) !== signY )
    // {
    //     // y = prime - y
    //     yBig = prime.sub( yBig );
    // }

    // return {
    //     x: x,
    //     y: yBig.toUint8Array()
    // };
}
//We want to use point compression back and forth to reduce bandwidth at the cost of computation overhead
//https://stackoverflow.com/questions/17171542/algorithm-for-elliptic-curve-point-compression/53480175#53480175


//const bigInt = require("big-integer");

// /**
//  * Point compress elliptic curve key
//  * @param {Uint8Array} x component
//  * @param {Uint8Array} y component
//  * @return {Uint8Array} Compressed representation
//  */
// function ECPointCompress( x, y )
// {
//     const out = new Uint8Array( x.length + 1 );

//     out[0] = 2 + ( y[ y.length-1 ] & 1 );
//     out.set( x, 1 );

//     return out;
// }


// // Consts for P256 curve. Adjust accordingly
// const two = new bigInt(2),
// // 115792089210356248762697446949407573530086143415290314195533631308867097853951
// prime = two.pow(256).sub( two.pow(224) ).add( two.pow(192) ).add( two.pow(96) ).sub(1),
// b = new bigInt( '41058363725152142129326129780047268409114441015993725554835256314039467401291' ),
// // Pre-computed value, or literal
// pIdent = prime.add(1).divide(4); // 28948022302589062190674361737351893382521535853822578548883407827216774463488


// /**
//  * Point decompress NIST curve
//  * @param {Uint8Array} Compressed representation
//  * @return {Object} Explicit x & y
//  */
// function ECPointDecompress( comp )
// {
//     const signY = comp[0] - 2, // This value must be 2 or 3. 4 indicates an uncompressed key, and anything else is invalid.
//     x = comp.subarray(1),
//     // Import x into bigInt library
//     xBig = new bigInt( x );

//     // y^2 = x^3 - 3x + b
//     var yBig = xBig.pow(3).sub( xBig.multiply(3) ).add( b ).modPow( pIdent, prime );

//     // If the parity doesn't match it's the *other* root
//     if( yBig.mod(2) !== signY )
//     {
//         // y = prime - y
//         yBig = prime.sub( yBig );
//     }

//     return {
//         x: x,
//         y: yBig.toUint8Array()
//     };
// }

// const bigInt = require("big-integer");

// // Consts for P256 curve. Adjust accordingly
// const two = new bigInt(2),
// // 115792089210356248762697446949407573530086143415290314195533631308867097853951
// prime = two.pow(256).subtract( two.pow(224) ).add( two.pow(192) ).add( two.pow(96) ).subtract(1),
// b = new bigInt( '41058363725152142129326129780047268409114441015993725554835256314039467401291' ),
// // Pre-computed value, or literal
// // 28948022302589062190674361737351893382521535853822578548883407827216774463488
// pIdent = prime.add(1).divide(4);

// function pad_with_zeroes(number, length) {
//     var retval = '' + number;
//     while (retval.length < length) {
//         retval = '0' + retval;
//     }
//     return retval;
// }

// /**
//  * Point decompress NIST curve
//  * @param {string} Compressed representation in hex string
//  * @return {string} Uncompressed representation in hex string
//  */
// function ECPointDecompress( comp ) {
//     var signY = new Number(comp[1]) - 2;
//     var x = new bigInt(comp.substring(2), 16);
//     // y^2 = x^3 - 3x + b
//     var y = x.pow(3).subtract( x.multiply(3) ).add( b ).modPow( pIdent, prime );
//     // If the parity doesn't match it's the *other* root
//     if( y.mod(2).toJSNumber() !== signY ) {
//         // y = prime - y
//         y = prime.subtract( y );
//     }
//     return '04' + pad_with_zeroes(x.toString(16), 64) + pad_with_zeroes(y.toString(16), 64);
// }




