
// XXX For node only: clobber the random bytes
var $crypto = require('crypto');
_randombytes = function(ptr, len) {
  var buf = $crypto.randomBytes(len);
  for (var i = 0; i < len; i++) {
    HEAPU8[ptr++] = buf[i];
  }
};

var NACL = {
  declare: function(name) {
    var func =  eval('_' + name);
    if (!func) {
      console.log('no such function: ' + '_' + name);
    }
    return func;
  }
};

////////////////////////////////////////////////////////////////////////////////
// Strings, Types

function makeSizey() {
  var addr = STACKTOP;
  Runtime.stackAlloc(8);
  return addr;
}
function fetchSizey(addr) {
  return HEAP32[addr >> 2];
}

function ustr_t(x) {
  return function() {
    var addr = STACKTOP;
    Runtime.stackAlloc(x);
    return addr;
  };
}
function alloc_ustr(len) {
  var addr = STACKTOP;
  Runtime.stackAlloc(len);
  return addr;
}

/**
 * Convert an 8-bit binary string of known length to a JavaScript string.
 */
function BinStrToJSStr(ptr, offset, length) {
  var s = "";
  for (var i = offset; i < length; i++) {
    s += String.fromCharCode(HEAPU8[ptr + i]);
  }
  return s;
}

/**
 * Convert a *null-terminated* utf8-encoded string stored in a ctypes rep to a
 *  JS string rep.  You need to make sure you allocated space for an put a nul
 *  in!
 */
function Utf8StrToJSStr(ptr, offset) {
  ptr += offset;
  var s = "";
  for(;;) {
    var c = HEAPU8[ptr++];
    // (null-terminator?)
    if (c === 0)
      break;
    // multi-blurn! I mean, byte
    if (c & 0x80) {
      // 3-byte
      if (c & 0x20) {
        c = ((c & 0xf) << 12) |
            ((HEAPU8[ptr++] & 0x3f) << 6) |
            (HEAPU8[ptr++] & 0x3f);
      }
      // 2-byte
      else {
        c = ((c & 0x1f) << 6) |
            (HEAPU8[ptr++] & 0x3f);
      }
    }
    s += String.fromCharCode(c);
  }
  return s;
}

/**
 * Convert a JS string that contains a (binary-encoded) utf8-string inside of it
 *  into the proper JS string representation of that string, effectively just
 *  performing utf-8 decoding.
 */
function JSUtf8StrToJSStr(u8str) {
  var binStr = JSStrToBinStr(u8str, 0);
  return Utf8StrToJSStr(binStr, 0);
}

/**
 * Convert a JS string containing an 8-bit binary string into a ctypes 8-bit
 *  binary string.
 */
function JSStrToBinStr(jsStr, offset) {
  var ptr = alloc_ustr(jsStr.length - offset), length = jsStr.length;
  for (var i = offset; i < length; i++, ptr++) {
    HEAPU8[ptr] = jsStr.charCodeAt(i);
  }
  return ptr;
}

/**
 * Convert a standard utf-16 JS string into a ctypes 8-bit utf-8 encoded string.
 */
function JSStrToUtf8Str(jsStr) {
  var arr = [], length = jsStr.length;
  for (var i = 0; i < length; i++) {
    var c = jsStr.charCodeAt(i);
    if (c <= 0x7f) {
      arr.push(c);
    }
    else if (c <= 0x7ff) {
      arr.push(0xc | (c >> 6));
      arr.push(0x8 | (c & 0x3f));
    }
    else {
      arr.push(0xe | (c >> 12));
      arr.push(0x8 | ((c >> 6) & 0x3f));
      arr.push(0x8 | (c & 0x3f));
    }
  }
  return allocate(arr, 'i8', ALLOC_STACK);
}

// XXX we really want to expose friendly symbols instead of requiring this
//  absurdity...
const SIGN_IMPL = "_edwards25519sha512batch_ref",
      BOX_IMPL = "_curve25519xsalsa20poly1305_ref",
      SECRETBOX_IMPL = "_xsalsa20poly1305_ref",
      AUTH_IMPL = "_hmacsha512256_ref",
      HASH_IMPL = "_sha512_ref";

////////////////////////////////////////////////////////////////////////////////
// Custom Exceptions

function gimmeStack() {
  try {
    throw new Error("blah");
  }
  catch(ex) {
    return ex.stack;
  }
  return null;
}

function BadBoxError(msg) {
  this.message = msg;
  this.stack = gimmeStack();
}
exports.BadBoxError = BadBoxError;
BadBoxError.prototype = {
  __proto__: Error.prototype,
 name: 'BadBoxError',
};

function BadSignatureError(msg) {
  this.message = msg;
  this.stack = gimmeStack();
}
exports.BadSignatureError = BadSignatureError;
BadSignatureError.prototype = {
  __proto__: Error.prototype,
 name: 'BadSignatureError',
};

function BadSecretBoxError(msg) {
  this.message = msg;
  this.stack = gimmeStack();
}
exports.BadSecretBoxError = BadSecretBoxError;
BadSecretBoxError.prototype = {
  __proto__: Error.prototype,
 name: 'BadSecretBoxError',
};

function BadAuthenticatorError(msg) {
  this.message = msg;
  this.stack = gimmeStack();
}
exports.BadAuthenticatorError = BadAuthenticatorError;
BadAuthenticatorError.prototype = {
  __proto__: Error.prototype,
 name: 'BadAuthenticatorError',
};

////////////////////////////////////////////////////////////////////////////////
// Random Data Support

function random_byte_getter(howmany) {
  // we can permanently allocate an array for this...
  var arr = allocate(howmany, 'i8', ALLOC_NORMAL);
  return function() {
    _randombytes(arr, howmany);
    return BinStrToJSStr(arr, 0, howmany);
  };
}

////////////////////////////////////////////////////////////////////////////////
// Signing


const crypto_sign_SECRETKEYBYTES = 64,
      crypto_sign_PUBLICKEYBYTES = 32,
      crypto_sign_BYTES = 64;

const SignPublicKeyBstr = ustr_t(crypto_sign_PUBLICKEYBYTES),
      SignSecretKeyBstr = ustr_t(crypto_sign_SECRETKEYBYTES);

var crypto_sign_keypair = NACL.declare("crypto_sign" + SIGN_IMPL + "_keypair");

exports.sign_keypair = function() {
  var pk = SignPublicKeyBstr(),
      sk = SignSecretKeyBstr();
console.log("making keypair");
  if (crypto_sign_keypair(pk, sk) !== 0)
    throw new BadSignatureError("inexplicably failed to create keypair");
console.log("converting keypair");
  return {
    sk: BinStrToJSStr(sk, 0, crypto_sign_SECRETKEYBYTES),
    pk: BinStrToJSStr(pk, 0, crypto_sign_PUBLICKEYBYTES),
  };
};

var crypto_sign = NACL.declare("crypto_sign" + SIGN_IMPL);

exports.sign = function(jsm, sk) {
  if (sk.length !== crypto_sign_SECRETKEYBYTES)
    throw new BadSignatureError("incorrect secret-key length");

  var m = JSStrToBinStr(jsm, 0), m_len = m.length;
  var sm = alloc_ustr(m_len + crypto_sign_BYTES);

  var sm_len = makeSizey();
  if (crypto_sign(sm, sm_len, m, m_len, JSStrToBinStr(sk, 0)) !== 0)
    throw new BadSignatureError("inexplicably failed to sign message");

  return BinStrToJSStr(sm, 0, fetchSizey(sm_len));
};

exports.sign_utf8 = function(jsm, sk) {
  if (sk.length !== crypto_sign_SECRETKEYBYTES)
    throw new BadSignatureError("incorrect secret-key length");
console.log("CONVERTING");
  var m = JSStrToUtf8Str(jsm, 0), m_len = m.length - 1; //eat nul
  var sm = alloc_ustr(m_len + crypto_sign_BYTES);

  var sm_len = makeSizey();
console.log("SIGNGING");
  if (crypto_sign(sm, sm_len, m, m_len, JSStrToBinStr(sk, 0)) !== 0)
    throw new BadSignatureError("inexplicably failed to sign message");
console.log("SIGNED");
  return BinStrToJSStr(sm, 0, fetchSizey(sm_len));
};

var crypto_sign_open = NACL.declare("crypto_sign" + SIGN_IMPL + "_open");

exports.sign_open = function(js_sm, pk) {
  if (pk.length !== crypto_sign_PUBLICKEYBYTES)
    throw new BadSignatureError("incorrect public-key length: " + pk.length);
  if (js_sm.length < crypto_sign_BYTES)
    throw new BadSignatureError(
      "message is smaller than the minimum signed message size");

  var sm = JSStrToBinStr(js_sm, 0), sm_len = sm.length;

  var m = alloc_ustr(sm_len),
      m_len = makeSizey();

  if (crypto_sign_open(m, m_len, sm, sm_len, JSStrToBinStr(pk, 0)))
    throw new BadSignatureError("ciphertext fails verification");

  return BinStrToJSStr(m, 0, fetchSizey(m_len));
};

exports.sign_open_utf8 = function(js_sm, pk) {
  if (pk.length !== crypto_sign_PUBLICKEYBYTES)
    throw new BadSignatureError("incorrect public-key length: " + pk.length);
  if (js_sm.length < crypto_sign_BYTES)
    throw new BadSignatureError(
      "message is smaller than the minimum signed message size");

  var sm = JSStrToBinStr(js_sm, 0), sm_len = sm.length;

  var m = alloc_ustr(sm_len + 1), // null terminator needs a spot
      m_len = makeSizey();

  if (crypto_sign_open(m, m_len, sm, sm_len, JSStrToBinStr(pk, 0)))
    throw new BadSignatureError("ciphertext fails verification");
  m[m_len] = 0;

  return Utf8StrToJSStr(m, 0, fetchSizey(m_len));
};

exports.sign_peek = function(js_sm) {
  return js_sm.substring(crypto_sign_BYTES / 2,
                         js_sm.length - crypto_sign_BYTES / 2);
};

exports.sign_peek_utf8 = function(js_sm) {
  var binstr = js_sm.substring(crypto_sign_BYTES / 2,
                               js_sm.length - crypto_sign_BYTES / 2);
  return JSUtf8StrToJSStr(binstr);
};

