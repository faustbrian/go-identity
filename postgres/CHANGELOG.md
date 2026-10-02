# Changelog

## Unreleased

- Add bounded primary tenant/user reads with lossless uint64 version decoding,
  strict projection validation and redacted failure classifications. This
  initial development adapter does not yet include its owned migrations or
  durable mutation coordinator and is not ready for adoption.
