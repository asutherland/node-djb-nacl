var nacl = require('nacl');

/**
 * Test the signature generation and verification using freshly generated keys.
 */
exports.testSigning = function(test) {
  // Create public/secret keys {pk, sk}
  var keys = nacl.sign_keypair();

  // Sign a message with the secret key
  var message = 'Hello World!';
  var signed_message = nacl.sign(message, keys.sk);

  // Verify the (valid) signed message.
  var checked_message = nacl.sign_open(signed_message, keys.pk);
  test.equal(message, checked_message);

  // Verify that a gibberish signed message does not pass.
  test.throws(function() {
    var gibberish_signed_message = 'I am not actually signed';
    var bad_checked_message = nacl.sign_open(gibberish_signed_message, keys.pk);

  });

  // Verify that a message signed with a different public key does not pass.
  var alt_keys = nacl.sign_keypair();
  var alt_signed_message = nacl.sign(message, alt_keys.sk);

  test.throws(function() {
    var alt_checked_message = nacl.sign_open(alt_signed_message, keys.pk);
  });
};


/**
 * Test the public-key encryption and decryption using freshly generated keys
 * and nonces.
 */
exports.testPublicKeyEncryption = function(test) {
  var sender_keys = nacl.box_keypair(),
      recipient_keys = nacl.box_keypair();
  // Random nonces are unlikely to collide and we are less likely to violate
  // the requirement forbidding reusing nonces for a given sender/recipient pair
  // than we try and do it ourselves.
  var nonce = nacl.box_random_nonce();

  var message = 'Hush hush, world!';

  var boxed_message = nacl.box(message, nonce,
                               recipient_keys.pk, sender_keys.sk);

  var unboxed_message = nacl.box_open(boxed_message, nonce,
                                      sender_keys.pk, recipient_keys.sk);
  test.equal(boxed_message, unboxed_message);

};
