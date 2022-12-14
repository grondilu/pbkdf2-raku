#!/usr/bin/env raku
use Test;
plan 6;

use PBKDF2;
use Digest::HMAC:auth<grondilu>;
use Digest::SHA1;

sub hmac-sha1(Blob $input, blob8 $salt) returns Blob {
  hmac(key => $salt, msg => $input, hash => &sha1, block-size => 64);
  #my Str $salt-hex = $salt».fmt("%02x").join;
  #given run |<openssl dgst -sha1 -mac hmac -macopt>, "hexkey:$salt-hex", '-binary',
  #  :in, :out, :bin {
  #  .in.write: $input;
  #  .in.close;
  #  return .out.slurp: :close;
  #}
}

is pbkdf2("password", :prf(&hmac-sha1), :salt("salt"), :c(1), :dkLen(20)),
buf8.new(<0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6>.map(*.parse-base(16)));

is pbkdf2("password", :prf(&hmac-sha1), :salt("salt"), :c(2), :dkLen(20)),
buf8.new(<ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57>.map(*.parse-base(16)));

is pbkdf2("password", :prf(&hmac-sha1), :salt("salt"), :c(4096), :dkLen(20)),
buf8.new(<4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1>.map(*.parse-base(16)));

skip "this would take way too long"; #`{
is pbkdf2("password", :prf(&hmac-sha1), :salt("salt".encode), :c(16777216), :dkLen(20)),
buf8.new(<ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84>.map(*.parse-base(16)));
}

is pbkdf2("passwordPASSWORDpassword", :prf(&hmac-sha1), :salt("saltSALTsaltSALTsaltSALTsaltSALTsalt".encode), :c(4096), :dkLen(25)),
buf8.new(<3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38>.map(*.parse-base(16)));

is pbkdf2("pass\0word", :prf(&hmac-sha1), :salt("sa\0lt"), :c(4096), :dkLen(16)),
buf8.new(<56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3>.map(*.parse-base(16)));

# vi: ft=raku
