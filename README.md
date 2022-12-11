# pbkdf2-raku

PBKDF2 in pure raku.  Speed will mostly depend on the pseudo-random function used.

## Synopsis

```raku
use PBKDF2;
use Digest::MD5;

say pbkdf2 "password",
  :salt("salt"),
  :prf(&md5 ∘ &[~]),
  :c(10),
  :dkLen(32);
```

