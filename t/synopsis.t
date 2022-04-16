#!/usr/bin/env raku
use Test;
plan 1;

use PBKDF2;
use Digest;

lives-ok { pbkdf2 "password",
  :salt("salt".encode),
  :prf({ md5($^a ~ $^b) }),
  :c(1096),
  :dkLen(32);
}

# vi: ft=raku
