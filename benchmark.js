var nacl = require('nacl');
var microtime = require('microtime');

const DO_EACH = 128;

var BINNONREP = '\u0000\u0001\u0002\u0003\u00004\u0000' +
                '\u0000\u0005\u0006\u0007\u00008\u0000' +
                '\u0000\u0009\u000a\u000b\u0000c\u0000' +
                '\u0000\u0011\u0012\u0013\u00014\u0000' +
                '\u0000\u0015\u0016\u0017\u00018\u0000' +
                '\u0000\u0019\u001a\u001b\u0001c\u0000' +
                '\u0000\u0021\u0022\u0023\u00024\u0000' +
                '\u0000\u0025\u0026\u0027\u00028\u0000' +
                '\u0000\u0029\u002a\u002b\u0002c\u0000'; // 54 bytes

var ZEROES_8 = '\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000';
var ZEROES_16 = ZEROES_8 + ZEROES_8;
var ZEROES_64 = ZEROES_16 + ZEROES_16 + ZEROES_16 + ZEROES_16;
var ZEROES_256 = ZEROES_64 + ZEROES_64 + ZEROES_64 + ZEROES_64;
var ZEROES_1024 = ZEROES_256 + ZEROES_256 + ZEROES_256 + ZEROES_256;
var ZEROES_4096 = ZEROES_1024 + ZEROES_1024 + ZEROES_1024 + ZEROES_1024;

function report(started, finished, count, payloadLen, what) {
  console.log(what, count, 'of', payloadLen, 'bytes in',
              finished - started, 'uS for a per operation cost of',
              (finished - started) / DO_EACH, 'uS');
}

function benchmarkSignatures(payload, signer, opener) {
  var started, finished, i;
  var keypairs = [];
  var sigs = [];
  var verified = [];

  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    keypairs.push(nacl.sign_keypair());
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, 'n/a', 'generate signing keypairs:');

  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    sigs.push(signer(payload, keypairs[i].sk));
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, payload.length, 'generate signatures:');

  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    verified.push(opener(sigs[i], keypairs[i].pk));
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, payload.length, 'verified signatures:');

  console.log();
}

function benchmarkPublicKeyEncryption(payload, boxer, unboxer) {
  var started, finished, i;
  var keypairs = [];
  var nonces = [];
  var boxed = [];
  var unboxed = [];

  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    keypairs.push(nacl.box_keypair());
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, 'n/a', 'generate boxing keypairs:');

  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    nonces.push(nacl.box_random_nonce());
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, 'n/a', 'generate nonces:');


  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    boxed.push(boxer(payload, nonces[i],
                     keypairs[(DO_EACH + i - 1)%DO_EACH].pk,
                     keypairs[i].sk));
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, payload.length, 'boxify:');

  started = microtime.now();
  for (i = 0; i < DO_EACH; i++) {
    unboxed.push(unboxer(boxed[i], nonces[i],
                         keypairs[i].pk,
                         keypairs[(DO_EACH + i - 1)%DO_EACH].sk));
  }
  finished = microtime.now();
  report(started, finished, DO_EACH, payload.length, 'open boxes:');

  console.log();
}

// XXX the garbage collector could be involved...
console.log("=== Signatures ===");
benchmarkSignatures(BINNONREP, nacl.sign, nacl.sign_open);
benchmarkSignatures(ZEROES_256, nacl.sign, nacl.sign_open);
benchmarkSignatures(ZEROES_1024, nacl.sign, nacl.sign_open);
benchmarkSignatures(ZEROES_4096, nacl.sign, nacl.sign_open);

console.log("\n");

console.log("=== Public Key Encryption ===");
console.log("note: this is way faster than the signatures because it is");
console.log("computing a shared secret and going from there.  Do *not* try");
console.log("and use this as a basis for a (faster) signature system!");
console.log();

benchmarkPublicKeyEncryption(BINNONREP, nacl.box, nacl.box_open);
benchmarkPublicKeyEncryption(ZEROES_256, nacl.box, nacl.box_open);
benchmarkPublicKeyEncryption(ZEROES_1024, nacl.box, nacl.box_open);
benchmarkPublicKeyEncryption(ZEROES_4096, nacl.box, nacl.box_open);
