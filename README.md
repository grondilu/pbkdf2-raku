# pbkdf2-raku

PBKDF2 in pure raku.  Speed will mostly depend on the pseudo-random function used.

## Synopsis

```raku
use PBKDF2;
use Digest;

say pbkdf2 "password",
  :salt("salt".encode),
  :prf({ md5($^a ~ $^b) }),
  :c(10),
  :dkLen(32);
```

