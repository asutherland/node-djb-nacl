var nacl = require('nacl');
var $buf = require('buffer');
// nodeunit actually has a different signature for throws from assert, and
//  assert's is much better.
var assert = require('assert');

// Use a bunch of zeroes as our binary string test as they are proven to screw
//  us up in utf8 mode.
var ZEROES_8 = '\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000';
var ZEROES_16 = ZEROES_8 + ZEROES_8;
var ZEROES_64 = ZEROES_16 + ZEROES_16 + ZEROES_16 + ZEROES_16;

// Also use a stream of numbers with binary zeroes mixed in so that repetition
//  causes a failure.  (We have had a problem where bits of the string got
//  repeated, which is obviously not useful.)
var BINNONREP = '\u0000\u0001\u0002\u0003\u00004\u0000' +
                '\u0000\u0005\u0006\u0007\u00008\u0000' +
                '\u0000\u0009\u000a\u000b\u0000c\u0000' +
                '\u0000\u0011\u0012\u0013\u00014\u0000' +
                '\u0000\u0015\u0016\u0017\u00018\u0000' +
                '\u0000\u0019\u001a\u001b\u0001c\u0000' +
                '\u0000\u0021\u0022\u0023\u00024\u0000' +
                '\u0000\u0025\u0026\u0027\u00028\u0000' +
                '\u0000\u0029\u002a\u002b\u0002c\u0000'; // 54 bytes

var ALPHA_STEW = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' +
                 'abcdefghijklmnopqrstuvwxyz0123456789';

var JSON_STEW = JSON.stringify({
  a: 'b',
  c: ['d', 5, -10, {e: 'f'}],
  g: {h: 'i', j: 12},
});

// XXX if we had non-ASCII messages tested, this would screw up as it needs to
//  know whether to interpret as utf8 in that case...
function hexify(bs) {
  var buf = new $buf.Buffer(bs, 'binary');
  return buf.toString('hex');
}

function checkSignatureOf(message, binaryMode, test) {
  console.log("===== Planning to sign: '" + message + "' aka " +
              hexify(message));
  var signer, opener, peeker;
  if (binaryMode) {
    signer = nacl.sign;
    opener = nacl.sign_open;
    peeker = nacl.sign_peek;
  }
  else {
    signer = nacl.sign_utf8;
    opener = nacl.sign_open_utf8;
    peeker = nacl.sign_peek_utf8;
  }

  // Create public/secret keys {pk, sk}
  var keys = nacl.sign_keypair();

  console.log('SIGNATURE KEYS',
              'sk', keys.sk.length, hexify(keys.sk),
              'pk', keys.pk.length, hexify(keys.pk));

  // Sign a message with the secret key
  console.log("SIGN", message.length, message);
  var signed_message = signer(message, keys.sk);

  console.log("SIGNED", signed_message.length, hexify(signed_message));
  test.notEqual(message, signed_message);

  var peeked_message = peeker(signed_message);
  console.log("PEEKED", peeked_message.length, peeked_message);
  test.equal(message, peeked_message);

  // Verify the (valid) signed message.
  var checked_message = opener(signed_message, keys.pk);
  console.log("OPENED", checked_message.length, checked_message);
  test.equal(message, checked_message);

  // The minimum message size is 64 bytes because of the hash and the signature,
  //  but we need to make sure we don't die with something smaller, as nacl
  //  does not guard against this and will crash us hard.
  var too_small_gibberish_signed_message = 'I am not actually signed'; // 24
  var gibberish_signed_message = '';
  while (gibberish_signed_message.length < 64)
    gibberish_signed_message += too_small_gibberish_signed_message;

  // Verify that gibberish signed messages do not pass.
  assert.throws(function() {
    var bad_checked_message =
      opener(too_small_gibberish_signed_message, keys.pk);
  }, /message is smaller than the minimum signed message size/);
  assert.throws(function() {
    var bad_checked_message = opener(gibberish_signed_message, keys.pk);
  }, /ciphertext fails verification/);

  // Verify that a message signed with a different public key does not pass.
  var alt_keys = nacl.sign_keypair();
  var alt_signed_message = signer(message, alt_keys.sk);

  assert.throws(function() {
    var alt_checked_message = opener(alt_signed_message, keys.pk);
  }, /ciphertext fails verification/);
}

/**
 * Test the signature generation and verification using freshly generated keys.
 */
exports.testSigning = function(test) {
  checkSignatureOf('Hello World!', false, test);
  checkSignatureOf(ALPHA_STEW, false, test);
  checkSignatureOf(JSON_STEW, false, test);

  checkSignatureOf(ZEROES_64, true, test);
  checkSignatureOf(BINNONREP, true, test);

  test.done();
};

function checkPublicKeyRoundTripOf(message, binaryMode, test) {
  var boxer, unboxer;
  if (binaryMode) {
    boxer = nacl.box;
    unboxer = nacl.box_open;
  }
  else {
    boxer = nacl.box_utf8;
    unboxer = nacl.box_open_utf8;
  }

  console.log("===== Planning to encrypt: '" + message + "' aka " +
              hexify(message));
  var sender_keys = nacl.box_keypair(),
      recip_keys = nacl.box_keypair();
  console.log('PK SENDER sk', sender_keys.sk.length, hexify(sender_keys.sk));
  console.log('PK SENDER pk', sender_keys.pk.length, hexify(sender_keys.pk));
  console.log('PK RECIP sk', recip_keys.sk.length, hexify(recip_keys.sk));
  console.log('PK RECIP pk', recip_keys.pk.length, hexify(recip_keys.pk));

  // Random nonces are unlikely to collide and we are less likely to violate
  //  the requirement forbidding reusing nonces for a given sender/recip pair
  //  than we try and do it ourselves.
  var nonce = nacl.box_random_nonce();
  console.log('NONCE', hexify(nonce));

  console.log('BOX', message.length, message);
  var boxed_message = boxer(message, nonce,
                            recip_keys.pk, sender_keys.sk);
  console.log('BOXED', boxed_message.length, hexify(boxed_message));
  test.notEqual(message, boxed_message);

  var unboxed_message = unboxer(boxed_message, nonce,
                                sender_keys.pk, recip_keys.sk);
  console.log('UNBOX', unboxed_message.length, unboxed_message);
  test.equal(message, unboxed_message);
}

/**
 * Test the public-key encryption and decryption using freshly generated keys
 * and nonces.
 */
exports.testPublicKeyEncryption = function(test) {
  // Check that our round-trip actually works...
  checkPublicKeyRoundTripOf('Hello World!', false, test);
  checkPublicKeyRoundTripOf(ALPHA_STEW, false, test);
  checkPublicKeyRoundTripOf(JSON_STEW, false, test);

  // Check that we don't break on true binary strings...
  checkPublicKeyRoundTripOf(ZEROES_64, true, test);
  checkPublicKeyRoundTripOf(BINNONREP, true, test);

  // The gibberish / wrong keys thing does not make a lot of sense in the
  //  encryption case, so we don't bother.

  test.done();
};
