# ChaCha20 in Emacs Lisp

This is a pure Emacs Lisp implementation of the [ChaCha20 stream
cipher][chacha20].

This library requires an Emacs built with integers at least 32 bits
wide. This typically means a 64-bit build of Emacs. If it passes the
test (`make check`), then you're good to go.

As you would expect, performance is abysmal. It's around 1000x slower
than the C reference.

## API

```el
(chacha20-create key iv)
```

Create a new ChaCha20 context initialized with the given 256-bit key
and 64-bit nonce. Both `key` and `iv` must be unibyte strings.

```el
(chacha20 context)
```

Generate the next 64 bytes of output in the form of a unibyte string.

```el
(chacha20-unpacked context)
```

Generate the next 64 bytes of output in the form of 16 32-bit
integers. Useful when using ChaCha20 as a PRNG.


[chacha20]: https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
