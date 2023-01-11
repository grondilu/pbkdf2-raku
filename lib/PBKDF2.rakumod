#!/usr/bin/env raku
unit module PBKDF2;

proto pbkdf2( $, :$salt, :&prf, UInt :$c, UInt :$dkLen) returns blob8 is export {*}

multi pbkdf2(Str   $password, :&prf,     :$salt, :$c, :$dkLen) { samewith $password.encode, :&prf, :$salt,              :$c, :$dkLen }
multi pbkdf2(blob8 $password, :&prf, Str :$salt, :$c, :$dkLen) { samewith $password,        :&prf, :salt($salt.encode), :$c, :$dkLen }

multi pbkdf2(blob8 $key, :&prf, blob8 :$salt, :$c, :$dkLen) {
  (
    [\~] map -> $seed {
      reduce * ~^ *, (
	$seed,
	{ prf($_, $key) } ... *
	#&prf.assuming(*, $key) ... *
      )[1..$c];
    } o
    { $salt ~ blob8.new(.polymod(256 xx 3).reverse) },
    1..Inf
  ).first(*.elems ≥ $dkLen)
  .subbuf(0, $dkLen)
}
  
