#!/usr/bin/env raku
use Test;
plan 1;

use PBKDF2;
use Digest::MD5;

lives-ok { pbkdf2 "password",
  :salt("salt"),
  :prf(&md5 ∘ &[~]),
  :c(1096),
  :dkLen(32);
}

# vi: ft=raku
