These are public artificial metadata goldens, frozen before binding the reviewer
tests to any D11 implementation. They contain no executable policy or scanner.

- `small-tree.json`: 591 raw ASCII bytes, no newline;
  SHA256 `171e51e9eea6c8e9d2cba4da52f583b9be56110fdae61f08ec72e1b22a60f024`.
  The hand-written rows describe `a/check.rego` = `b"alpha\n"`,
  `b/check.rego` = `b"beta\n"`, and `metadata.json` = `b'{"local":true}\n'`,
  plus explicit `a`, `b`, and `empty` directories. File payload hashes were
  independently computed with Python stdlib hashlib; no product helper was used.
- `legacy-invocation.json`: 315 raw ASCII bytes, no newline;
  SHA256 `9d7156d69ec15b3f7c2d43542aac6cbb57c0954b3c723cb5c70b1653f290d75c`.
  Independently encoded legacy digest payload with fixed portable path strings.
- `legacy-grant.json`: 1169 raw ASCII bytes, no newline;
  SHA256 `c66f94ca83a234cc9ce2c20892a041ed4506d7d0b2494f11d6ac24913544b89d`.
  Artificial legacy closed grant, externally fingerprinted by the test literal.

Payloads are constructed with explicit byte literals in tests, so checkout newline
conversion cannot change the intended file contents. The JSON goldens themselves
have no line ending to convert. Verify committed blobs against these exact hashes.
These tests establish structural transport behavior, never real execution evidence.
