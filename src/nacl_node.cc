/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at:
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is NaCl node binding.
 *
 * The Initial Developer of the Original Code is
 *   The Mozilla Foundation
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Andrew Sutherland <asutherland@asutherland.org>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include <string.h>

#include <v8.h>

#include <node.h>
#include <node_buffer.h>

#include "randombytes.h"
#include "crypto_box.h"
#include "crypto_sign.h"
#include "crypto_secretbox.h"
#include "crypto_auth.h"
#include "crypto_hash.h"

#include "nacl_node.h"

using namespace v8;
using namespace node;

static Persistent<Function> BadBoxErrorFunc;
static Persistent<Function> BadSignatureErrorFunc;
static Persistent<Function> BadSecretBoxErrorFunc;
static Persistent<Function> BadAuthenticatorErrorFunc;

// Evil macrology 

#define LEAVE_VIA_EXCEPTION(msg) \
 return ThrowException(Exception::Error(String::New(msg)));

#define LEAVE_VIA_CUSTOM_EXCEPTION(errorFunc, msg)      \
  {  Local<Value> argv[] = {String::New(msg)};          \
  Local<Value> Err = (errorFunc)->NewInstance(1, argv); \
  return ThrowException(Err);  }

#define BAIL_IF_NOT_N_ARGS(nargs,msg) \
 if (args.Length() != nargs) \
   LEAVE_VIA_EXCEPTION(msg);

/**
 * Convert a JS string used for message bytes (like an English or CJK message,
 *  meaning more than just ASCII) to a std::string holding utf8-encoded data.
 *
 * Defines a variable `varname` as a byproduct.
 *
 * @param narg The index of the argument.
 * @param varname The name of the variable to define and which to place the
 *                result value in.
 * @param humanlabel The name to use for the variable when throwing an exception
 *                   if the provided value is no good.
 */
#define COERCE_OR_BAIL_STR_ARG(narg,varname,humanlabel)      \
  if (!args[narg]->IsString())                               \
    LEAVE_VIA_EXCEPTION(humanlabel " needs to be a string"); \
  String::Utf8Value utf8_##varname(args[narg]);              \
  std::string varname(*utf8_##varname);

/**
 * Convert a JS string/buffer used for binary bytes (such as random bytes,
 *  crypto keys, and signed/encrypted messages) to a std::string holding
 *  binary-encoded data.
 *
 * Defines a variable `varname` as a byproduct.
 *
 * @param narg The index of the argument.
 * @param varname The name of the variable to define and which to place the
 *                result value in.
 * @param humanlabel The name to use for the variable when throwing an exception
 *                   if the provided value is no good.
 */
#define COERCE_OR_BAIL_BIN_STR_ARG(narg,varname,humanlabel)     \
  std::string varname;                                          \
  if (Buffer::HasInstance(args[narg])) {                        \
    v8::Handle<v8::Object> t##varname = args[narg]->ToObject(); \
    varname.replace(0, 0, Buffer::Data(t##varname),             \
                    Buffer::Length(t##varname));                \
  }                                                             \
  else if (args[narg]->IsString()) {                            \
    unsigned long nbytes = DecodeBytes(args[narg], BINARY);     \
    char *bytes = new char[nbytes];                             \
    DecodeWrite(bytes, nbytes, args[narg], BINARY);             \
    varname.replace(0, 0, bytes, nbytes);                       \
    delete[] bytes;                                             \
  }                                                             \
  else                                                          \
    LEAVE_VIA_EXCEPTION(humanlabel " needs to be a binary string or buffer")

/**
 * Converts a JS numeric argument to an unsigned long long.  Because we are not
 *  fancy and don't actually need the expressive range, we require that the
 *  argument needs to be a uint32.
 *
 * Defines a variable `varname` as a byproduct.
 *
 * @param narg The index of the argument.
 * @param varname The name of the variable to define and which to place the
 *                result value in.
 * @param humanlabel The name to use for the variable when throwing an exception
 *                   if the provided value is no good.
 */
#define COERCE_OR_BAIL_ULL_ARG(narg,varname,humanlabel) \
 if (!args[narg]->IsUint32()) \
   LEAVE_VIA_EXCEPTION(humanlabel " needs to be a uint32"); \
 unsigned long long varname(args[narg]->Uint32Value())

/**
 * Expression to return binary bytes from the std::string `strvar`.
 */
#define PREP_BIN_STR(strvar) \
  Encode(strvar.data(), strvar.length(), BINARY)

/**
 * Define a local `ret` to hold binary bytes from the std::string strvar.
 */
#define PREP_UTF8_STR_FOR_RETURN(strvar) \
  Local<Value> ret = Encode(strvar.data(), strvar.length(), UTF8)
#define PREP_BIN_STR_FOR_RETURN(strvar) \
  Local<Value> ret = Encode(strvar.data(), strvar.length(), BINARY)

#define PREP_TRUNCATED_BIN_STR_FOR_RETURN(strvar, truncateTo)           \
  Local<Value> ret = Encode(strvar.data(), truncateTo, BINARY)


#define PREP_BIN_CHARS_FOR_RETURN(cbuf, clen) \
  Local<Value> ret = Encode(cbuf, clen)

Handle<Value>
nacl_sign_keypair(const Arguments &args)
{
  HandleScope scope;

  std::string pk, sk;
  pk = crypto_sign_keypair(&sk);

  Local<Object> ret = Object::New();
  ret->Set(String::New("sk"), PREP_BIN_STR(sk));
  ret->Set(String::New("pk"), PREP_BIN_STR(pk));
  return scope.Close(ret);
}

Handle<Value>
nacl_sign(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 string args: message, secretkey");
  COERCE_OR_BAIL_BIN_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, sk, "secretkey");

  std::string sm;

  try {
    sm = crypto_sign(m, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(sm);
  return scope.Close(ret);
}

Handle<Value>
nacl_sign_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 string args: message, secretkey");
  COERCE_OR_BAIL_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, sk, "secretkey");

  std::string sm;

  try {
    sm = crypto_sign(m, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(sm);
  return scope.Close(ret);
}

Handle<Value>
nacl_sign_open(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 string args: signed_message, public_key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, sm, "signed_message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, pk, "public_key");

  // IMPORTANT!  nacl does not validate the size of 'sm' itself and is
  //  vulnerable to a crash-inducing unsigned wraparound.  So we explode
  //  for any input that is less than the minimum message size.
  if (sm.length() < crypto_sign_BYTES)
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSignatureErrorFunc,
      "message is smaller than the minimum signed message size");

  std::string m;
  try {
    m = crypto_sign_open(sm, pk);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSignatureErrorFunc, s);
  }

  PREP_BIN_STR_FOR_RETURN(m);
  return scope.Close(ret);
}

Handle<Value>
nacl_sign_open_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 string args: signed_message, public_key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, sm, "signed_message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, pk, "public_key");

  // IMPORTANT!  nacl does not validate the size of 'sm' itself and is
  //  vulnerable to a crash-inducing unsigned wraparound.  So we explode
  //  for any input that is less than the minimum message size.
  if (sm.length() < crypto_sign_BYTES)
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSignatureErrorFunc,
      "message is smaller than the minimum signed message size");

  std::string m;
  try {
    m = crypto_sign_open(sm, pk);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSignatureErrorFunc, s);
  }

  PREP_UTF8_STR_FOR_RETURN(m);
  return scope.Close(ret);
}


/**
 * Let us see the payload of the signed blob before authenticating it.  This
 *  allows us to use the contents to figure out what public key we should be
 *  using to authenticate the blob, etc.  Obviously, for a malformed message
 *  what you may get is gibberish.
 */
Handle<Value>
nacl_sign_peek(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(1, "Need 1 string arg: signed_message");
  COERCE_OR_BAIL_BIN_STR_ARG(0, sm, "signed_message");

  if (sm.length() < crypto_sign_BYTES)
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSignatureErrorFunc,
      "message is smaller than the minimum signed message size");

  // (We could just have sliced the input string without going to std::string
  //  too.)
  Local<Value> ret = Encode(sm.data() + crypto_sign_BYTES/2,
                            sm.length() - crypto_sign_BYTES,
                            BINARY);
  return scope.Close(ret);
}

Handle<Value>
nacl_sign_peek_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(1, "Need 1 string arg: signed_message");
  COERCE_OR_BAIL_BIN_STR_ARG(0, sm, "signed_message");

  if (sm.length() < crypto_sign_BYTES)
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSignatureErrorFunc,
      "message is smaller than the minimum signed message size");

  // (We could just have sliced the input string without going to std::string
  //  too.)
  Local<Value> ret = Encode(sm.data() + crypto_sign_BYTES/2,
                            sm.length() - crypto_sign_BYTES,
                            UTF8);
  return scope.Close(ret);
}


Handle<Value>
nacl_box_keypair(const Arguments &args)
{
  HandleScope scope;

  std::string pk, sk;
  pk = crypto_box_keypair(&sk);

  Local<Object> ret = Object::New();
  ret->Set(String::New("sk"), PREP_BIN_STR(sk));
  ret->Set(String::New("pk"), PREP_BIN_STR(pk));
  return scope.Close(ret);
}

Handle<Value>
nacl_box(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(4, "Need 4 args: message, nonce, pubkey, secretkey");
  COERCE_OR_BAIL_BIN_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, pk, "public_key");
  COERCE_OR_BAIL_BIN_STR_ARG(3, sk, "secret_key");

  std::string c;

  try {
    c = crypto_box(m, n, pk, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(c);
  return scope.Close(ret);
}

Handle<Value>
nacl_box_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(4, "Need 4 args: message, nonce, pubkey, secretkey");
  COERCE_OR_BAIL_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, pk, "public_key");
  COERCE_OR_BAIL_BIN_STR_ARG(3, sk, "secret_key");

  std::string c;

  try {
    c = crypto_box(m, n, pk, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(c);
  return scope.Close(ret);
}

Handle<Value>
nacl_box_open(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(4,
                     "Need 4 args: ciphertext, nonce, pubkey, secretkey");
  COERCE_OR_BAIL_BIN_STR_ARG(0, c, "ciphertext_message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, pk, "public_key");
  COERCE_OR_BAIL_BIN_STR_ARG(3, sk, "secret_key");

  std::string m;
  try {
    m = crypto_box_open(c, n, pk, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadBoxErrorFunc, s);
  }

  PREP_BIN_STR_FOR_RETURN(m);
  return scope.Close(ret);
}

Handle<Value>
nacl_box_open_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(4,
                     "Need 4 args: ciphertext, nonce, pubkey, secretkey");
  COERCE_OR_BAIL_BIN_STR_ARG(0, c, "ciphertext_message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, pk, "public_key");
  COERCE_OR_BAIL_BIN_STR_ARG(3, sk, "secret_key");

  std::string m;
  try {
    m = crypto_box_open(c, n, pk, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadBoxErrorFunc, s);
  }

  PREP_UTF8_STR_FOR_RETURN(m);
  return scope.Close(ret);
}

////////////////////////////////////////////////////////////////////////////////
// Secretbox

Handle<Value>
nacl_secretbox(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(3, "Need 3 args: message, nonce, key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, k, "key");

  std::string c;

  try {
    c = crypto_secretbox(m, n, k);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(c);
  return scope.Close(ret);
}

Handle<Value>
nacl_secretbox_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(3, "Need 3 args: message, nonce, key");
  COERCE_OR_BAIL_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, k, "key");

  std::string c;

  try {
    c = crypto_secretbox(m, n, k);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(c);
  return scope.Close(ret);
}

Handle<Value>
nacl_secretbox_open(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(3,
                     "Need 3 args: ciphertext, nonce, key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, c, "ciphertext_message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, k, "key");

  std::string m;
  try {
    m = crypto_secretbox_open(c, n, k);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSecretBoxErrorFunc, s);
  }

  PREP_BIN_STR_FOR_RETURN(m);
  return scope.Close(ret);
}

Handle<Value>
nacl_secretbox_open_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(3,
                     "Need 3 args: ciphertext, nonce, key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, c, "ciphertext_message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, n, "nonce");
  COERCE_OR_BAIL_BIN_STR_ARG(2, k, "key");

  std::string m;
  try {
    m = crypto_secretbox_open(c, n, k);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadSecretBoxErrorFunc, s);
  }

  PREP_UTF8_STR_FOR_RETURN(m);
  return scope.Close(ret);
}

////////////////////////////////////////////////////////////////////////////////
// auth

Handle<Value>
nacl_auth(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 args: message, key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, k, "key");

  std::string a;

  try {
    a = crypto_auth(m, k);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(a);
  return scope.Close(ret);
}

Handle<Value>
nacl_auth_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 args: message, key");
  COERCE_OR_BAIL_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(1, k, "key");

  std::string a;

  try {
    a = crypto_auth(m, k);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_BIN_STR_FOR_RETURN(a);
  return scope.Close(ret);
}

Handle<Value>
nacl_auth_verify(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(3,
                     "Need 3 args: authenticator, message, key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, a, "authenticator");
  COERCE_OR_BAIL_BIN_STR_ARG(1, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(2, k, "key");

  try {
    crypto_auth_verify(a, m, k);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadAuthenticatorErrorFunc, s);
  }

  return scope.Close(Undefined());
}

Handle<Value>
nacl_auth_verify_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(3,
                     "Need 3 args: authenticator, message, key");
  COERCE_OR_BAIL_BIN_STR_ARG(0, a, "authenticator");
  COERCE_OR_BAIL_STR_ARG(1, m, "message");
  COERCE_OR_BAIL_BIN_STR_ARG(2, k, "key");

  try {
    crypto_auth_verify(a, m, k);
  }
  catch(const char *s) {
    LEAVE_VIA_CUSTOM_EXCEPTION(BadAuthenticatorErrorFunc, s);
  }

  return scope.Close(Undefined());
}

////////////////////////////////////////////////////////////////////////////////
// Hash

Handle<Value>
nacl_hash512_256(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(1,
                     "Need 1 arg: message");
  COERCE_OR_BAIL_BIN_STR_ARG(0, m, "message");

  std::string h;

  try {
    h = crypto_hash(m);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_TRUNCATED_BIN_STR_FOR_RETURN(h, 32);
  return scope.Close(ret);
}

Handle<Value>
nacl_hash512_256_utf8(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(1,
                     "Need 1 arg: message");
  COERCE_OR_BAIL_STR_ARG(0, m, "message");

  std::string h;

  try {
    h = crypto_hash(m);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  PREP_TRUNCATED_BIN_STR_FOR_RETURN(h, 32);
  return scope.Close(ret);
}



////////////////////////////////////////////////////////////////////////////////
// Random bytes / nonces

/** Maximum number of random bytes the user can request in a go. */
#define MAX_RANDOM_BYTES 256

Handle<Value>
nacl_randombytes(const Arguments &args)
{
  HandleScope scope;
  char buf[MAX_RANDOM_BYTES];

  BAIL_IF_NOT_N_ARGS(1, "Need 1 numeric arg: number of random bytes");
  COERCE_OR_BAIL_ULL_ARG(0, numbytes, "num_random_bytes");

  if (numbytes >= MAX_RANDOM_BYTES)
    LEAVE_VIA_EXCEPTION("You want too many random bytes!");

  randombytes(reinterpret_cast<unsigned char *>(&buf), numbytes);

  PREP_BIN_CHARS_FOR_RETURN(buf, numbytes);
  return scope.Close(ret);
}

Handle<Value>
nacl_box_random_nonce(const Arguments &args)
{
  HandleScope scope;
  char buf[crypto_box_NONCEBYTES];

  BAIL_IF_NOT_N_ARGS(0, "No arguments required/supported");

  randombytes(reinterpret_cast<unsigned char *>(&buf), crypto_box_NONCEBYTES);

  PREP_BIN_CHARS_FOR_RETURN(buf, sizeof(buf)/sizeof(buf[0]));
  return scope.Close(ret);
}

Handle<Value>
nacl_secretbox_random_nonce(const Arguments &args)
{
  HandleScope scope;
  char buf[crypto_secretbox_NONCEBYTES];

  BAIL_IF_NOT_N_ARGS(0, "No arguments required/supported");

  randombytes(reinterpret_cast<unsigned char *>(&buf),
              crypto_secretbox_NONCEBYTES);

  PREP_BIN_CHARS_FOR_RETURN(buf, sizeof(buf)/sizeof(buf[0]));
  return scope.Close(ret);
}

Handle<Value>
nacl_secretbox_random_key(const Arguments &args)
{
  HandleScope scope;
  char buf[crypto_secretbox_KEYBYTES];

  BAIL_IF_NOT_N_ARGS(0, "No arguments required/supported");

  randombytes(reinterpret_cast<unsigned char *>(&buf),
              crypto_secretbox_KEYBYTES);

  PREP_BIN_CHARS_FOR_RETURN(buf, sizeof(buf)/sizeof(buf[0]));
  return scope.Close(ret);
}

Handle<Value>
nacl_auth_random_key(const Arguments &args)
{
  HandleScope scope;
  char buf[crypto_auth_KEYBYTES];

  BAIL_IF_NOT_N_ARGS(0, "No arguments required/supported");

  randombytes(reinterpret_cast<unsigned char *>(&buf),
              crypto_auth_KEYBYTES);

  PREP_BIN_CHARS_FOR_RETURN(buf, sizeof(buf)/sizeof(buf[0]));
  return scope.Close(ret);
}


////////////////////////////////////////////////////////////////////////////////

#define NAMED_CONSTANT(target, name, constant) \
  (target)->Set(String::NewSymbol(name), Integer::New(constant), \
                static_cast<PropertyAttribute>(ReadOnly|DontDelete))

extern "C" void init(Handle<Object> target)
{
  HandleScope scope;

  // -- Define our error classes
  Local<Script> errInitScript = Script::New(String::NewSymbol(
    "function BadBoxError(msg) {\n"
    "  Error.captureStackTrace(this, BadBoxError);\n"
    "  this.message = msg;};\n"
    "BadBoxError.prototype = {\n"
    "  __proto__: Error.prototype, name: 'BadBoxError'};\n"
    ""
    "function BadSignatureError(msg) {\n"
    "  Error.captureStackTrace(this, BadSignatureError);\n"
    "  this.message = msg;};\n"
    "BadSignatureError.prototype = {\n"
    "  __proto__: Error.prototype, name: 'BadSignatureError'};"
    ""
    "function BadSecretBoxError(msg) {\n"
    "  Error.captureStackTrace(this, BadSecretBoxError);\n"
    "  this.message = msg;};\n"
    "BadSecretBoxError.prototype = {\n"
    "  __proto__: Error.prototype, name: 'BadSecretBoxError'};"
    ""
    "function BadAuthenticatorError(msg) {\n"
    "  Error.captureStackTrace(this, BadAuthenticatorError);\n"
    "  this.message = msg;};\n"
    "BadAuthenticatorError.prototype = {\n"
    "  __proto__: Error.prototype, name: 'BadAuthenticatorError'};"
    ), String::NewSymbol("nacl_node.cc"));
  errInitScript->Run();

  Local<Object> global = Context::GetCurrent()->Global();

  Local<String> bbeString = String::NewSymbol("BadBoxError");
  Local<Value> bbe = global->Get(bbeString);
  BadBoxErrorFunc = Persistent<Function>::New(Local<Function>::Cast(bbe));

  Local<String> bseString = String::NewSymbol("BadSignatureError");
  Local<Value> bse = global->Get(bseString);
  BadSignatureErrorFunc = Persistent<Function>::New(Local<Function>::Cast(bse));
  
  Local<String> bsbeString = String::NewSymbol("BadSecretBoxError");
  Local<Value> bsbe = global->Get(bsbeString);
  BadSecretBoxErrorFunc = Persistent<Function>::New(Local<Function>::Cast(bsbe));

  Local<String> baeString = String::NewSymbol("BadAuthenticatorError");
  Local<Value> bae = global->Get(baeString);
  BadAuthenticatorErrorFunc = Persistent<Function>::New(
                                Local<Function>::Cast(bae));

  target->Set(bbeString, bbe);
  target->Set(bseString, bse);
  target->Set(bsbeString, bsbe);
  target->Set(baeString, bae);

  NODE_SET_METHOD(target, "randombytes", nacl_randombytes);

  // -- signing
  NODE_SET_METHOD(target, "sign_keypair", nacl_sign_keypair);
  NODE_SET_METHOD(target, "sign", nacl_sign);
  NODE_SET_METHOD(target, "sign_open", nacl_sign_open);
  NODE_SET_METHOD(target, "sign_peek", nacl_sign_peek); // made-up-by-us

  NODE_SET_METHOD(target, "sign_utf8", nacl_sign_utf8);
  NODE_SET_METHOD(target, "sign_open_utf8", nacl_sign_open_utf8);
  NODE_SET_METHOD(target, "sign_peek_utf8", nacl_sign_peek_utf8); // made-up

  // -- boxing
  NAMED_CONSTANT(target, "box_PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES);
  NAMED_CONSTANT(target, "box_SECRETKEYBYTES", crypto_box_SECRETKEYBYTES);

  NODE_SET_METHOD(target, "box_keypair", nacl_box_keypair);
  NODE_SET_METHOD(target, "box", nacl_box);
  NODE_SET_METHOD(target, "box_open", nacl_box_open);

  NODE_SET_METHOD(target, "box_random_nonce", nacl_box_random_nonce); // made-up

  NODE_SET_METHOD(target, "box_utf8", nacl_box_utf8);
  NODE_SET_METHOD(target, "box_open_utf8", nacl_box_open_utf8);

  // -- secretboxing
  NAMED_CONSTANT(target, "secretbox_KEYBYTES", crypto_secretbox_KEYBYTES);

  NODE_SET_METHOD(target, "secretbox", nacl_secretbox);
  NODE_SET_METHOD(target, "secretbox_open", nacl_secretbox_open);

  NODE_SET_METHOD(target, "secretbox_random_nonce",
                          nacl_secretbox_random_nonce); // made-up
  NODE_SET_METHOD(target, "secretbox_random_key",
                          nacl_secretbox_random_key); // made-up

  NODE_SET_METHOD(target, "secretbox_utf8", nacl_secretbox_utf8);
  NODE_SET_METHOD(target, "secretbox_open_utf8", nacl_secretbox_open_utf8);

  // -- authing
  NAMED_CONSTANT(target, "auth_KEYBYTES", crypto_auth_KEYBYTES);

  NODE_SET_METHOD(target, "auth", nacl_auth);
  NODE_SET_METHOD(target, "auth_verify", nacl_auth_verify);

  NODE_SET_METHOD(target, "auth_random_key",
                          nacl_auth_random_key); // made-up

  NODE_SET_METHOD(target, "auth_utf8", nacl_auth_utf8);
  NODE_SET_METHOD(target, "auth_verify_utf8", nacl_auth_verify_utf8);

  // -- hash
  // we are exposing a 512 truncating to 256 mainly because:
  // a) I want a 32-byte hash, not a 64-byte hash.
  // b) I am being lazy and the C++ binding only exposes sha512.
  // c) nacl internally uses a 512-truncated-to-256 elsewhere, so this is not a
  //     particularly risky primitive to expose.
  NODE_SET_METHOD(target, "hash512_256", nacl_hash512_256);
  NODE_SET_METHOD(target, "hash512_256_utf8", nacl_hash512_256_utf8);
};
