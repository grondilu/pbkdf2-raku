#!/usr/bin/env raku
unit module PBKDF2;

proto pbkdf2(
  $,
  :&prf,
  blob8 :$salt,
  UInt :$c,
  UInt :$dkLen
) returns blob8 is export {*}

multi pbkdf2(Str $password, :&prf, :$salt, :$c, :$dkLen) {
  samewith $password.encode, :&prf, :$salt, :$c, :$dkLen
}

sub int_32_be(uint32 $i --> blob8) {
  blob8.new:
    $i +> 24 +& 0xff,
    $i +> 16 +& 0xff,
    $i +>  8 +& 0xff,
    $i +>  0 +& 0xff
    ;
}
 
multi pbkdf2(blob8 $key, :&prf, :$salt, :$c, :$dkLen) {
  my $dgst-length = &prf("foo".encode, "bar".encode).elems;
  my $l = ($dkLen + $dgst-length - 1) div $dgst-length;
  .subbuf(0,$dkLen) given [~] gather for 1..$l -> $i {
    take reduce -> $a, $b {
      blob8.new: $a.list »+^« $b.list
    }, (
      buf8.new($salt ~ int_32_be($i)), {
	$*ERR.printf("\rPBKFD2: bloc %d/%d, iteration %d/%d", $i, $l, ++$, $c);
	prf($_, $key)
      } ... *
    )[1..$c];
    $*ERR.printf("\n");
  }
}
  
