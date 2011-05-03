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


#include <v8.h>

#include "crypto_box.h"
#include "crypto_sign.h"

#include "nacl_node.h"

using namespace v8;

// Evil macrology 

#define LEAVE_VIA_EXCEPTION(msg) \
 return ThrowException(Exception::Error(String::new(msg)));

#define BAIL_IF_NOT_N_ARGS(nargs,msg) \
{ \
 if (args.Length() != nargs) { \
   LEAVE_VIA_EXCEPTION(msg);
 } \
}

#define COERCE_OR_BAIL_STR_ARG(narg,varname,humanlabel) \
{ \
 if (!args[narg]->IsString()) { \
   LEAVE_VIA_EXCEPTION(humanlabel " needs to be a string"); \
 } \
 else { \
   String::Utf8Value ts(args[narg]->ToString()); \
   varname = ts; \
 } \
}

Handle<Value>
nacl_sign_keypair(const Arguments &args)
{
  HandleScope scope;

  std::string pk, sk;
  pk = crypto_sign_keypair(&sk);

  Local<Object> ret = Object::New();
  ret->Set(String::New("sk"), String::New(sk));
  ret->Set(String::New("pk"), String::New(pk));
  return scope.Close(ret);
}

Handle<Value>
nacl_sign(const Arguments &args)
{
  HandleScope scope;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 string args: message, secretkey");
  COERCE_OR_BAIL_STR_ARG(0, m, "message");
  COERCE_OR_BAIL_STR_ARG(1, sk, "secretkey");

  std::string sm;

  try {
    sm = crypto_sign(m, sk);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  Local<String> ret = String::New(sm);
  return scope.Close(ret);
}

Handle<Value>
nacl_sign_open(const Arguments &args)
{
  HandleScope scope;

  std::string sm, pk;

  BAIL_IF_NOT_N_ARGS(2, "Need 2 string args: signed_message, public_key");
  COERCE_OR_BAIL_STR_ARG(0, sm, "signed_message");
  COERCE_OR_BAIL_STR_ARG(1, pk, "public_key");

  try {
    m = crypto_sign_open(sm, pk);
  }
  catch(const char *s) {
    LEAVE_VIA_EXCEPTION(s);
  }

  Local<String> ret = String::New(m);
  return scope.Close(ret);
}


// crypto_box_NONCEBYTES

extern "C" void init(Handle<Object> target)
{
  HandleScope scope;

  target->Set(String::New("sign_keypair"),
              FunctionTemplate::New(nacl_sign_keypair)->GetFunction());
  target->Set(String::New("sign"),
              FunctionTemplate::New(nacl_sign)->GetFunction());
  target->Set(String::New("sign_open"),
              FunctionTemplate::New(nacl_sign_open)->GetFunction());
  /*
  target->Set(String::New("box_keypair"),
              FunctionTemplate::New(nacl_box_keypair)->GetFunction());
  target->Set(String::New("box"),
              FunctionTemplate::New(nacl_box)->GetFunction());
  target->Set(String::New("box_open"),
              FunctionTemplate::New(nacl_box_open)->GetFunction());

  target->Set(String::New("box_random_nonce"),
              FunctionTemplate::New(nacl_box_random_nonce)->GetFunction());
  */
};
