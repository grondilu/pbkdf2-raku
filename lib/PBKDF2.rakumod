#!/usr/bin/env raku
unit module PBKDF2;

proto pbkdf2(
  $,
  :$salt,
  :&prf,
  UInt :$c,
  UInt :$dkLen
) returns blob8 is export {*}

multi pbkdf2(Str $password, :&prf, :$salt, :$c, :$dkLen) {
  samewith $password.encode, :&prf, :$salt, :$c, :$dkLen
}
multi pbkdf2(blob8 $password, :&prf, Str :$salt, :$c, :$dkLen) {
  samewith $password, :&prf, :salt($salt.encode), :$c, :$dkLen
}

sub int_32_be(uint32 $i --> blob8) {
    ;
}
 
multi pbkdf2(blob8 $key, :&prf, :$salt, :$c, :$dkLen) {
  my $dgst-length = &prf("foo".encode, "bar".encode).elems;
  my $l = ($dkLen + $dgst-length - 1) div $dgst-length;
  .subbuf(0,$dkLen) given [~] gather for 1..$l -> $i {
    take reduce -> $a, $b {
      blob8.new: $a.list »+^« $b.list
    }, (buf8.new($salt ~ blob8.new: (24, 16, 8, 0).map: { $i +> $_ +& 0xff }), {
	$*ERR.printf("\rPBKFD2: bloc %d/%d, iteration %d/%d", $i, $l, ++$, $c);
	prf($_, $key)
      } ... *
    )[1..$c];
    $*ERR.printf("\n");
  }
}
  
