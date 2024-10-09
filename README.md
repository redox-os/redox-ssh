# redox-ssh

A ssh client and server written entirely in Rust, primarily targeted at [Redox OS](http://redox-os.org).

Please note that implementation is far from compleation
and currently is not suitable for real usage.

## Features

Currently implemented features, ordered by priority:

- [x] SSH Server
- [ ] SSH Client
- Key Exchange algorithms
  - [x] `curve25519-sha256` (via
        [~~rust-crypto~~](https://github.com/DaGenix/rust-crypto)
        [curve25519-dalek](https://crates.io/crates/curve25519-dalek))
  - [ ] `diffie-hellman-group-exchange-sha1`
- Public Key algorithms
  - [x] `ssh-ed25519` (via
        [~~rust-crypto~~](https://github.com/DaGenix/rust-crypto)
        [ed25519-dalek](https://crates.io/crates/ed25519-dalek))
  - [ ] `ssh-rsa`
- Encryption algorithms
  - [x] `aes256-ctr` (via
        [~~rust-crypto~~](https://github.com/DaGenix/rust-crypto)
        [ctr](https://crates.io/crates/ctr) and [aes](https://crates.io/crates/aes))
  - [ ] `aes256-gcm`
- MAC algorithms
  - [x] `hmac-sha2-256` (via
        [~~rust-crypto~~](https://github.com/DaGenix/rust-crypto)
        [sha2](https://crates.io/crates/sha2) and [hmac](https://crates.io/crates/hmac))
- Shell
  - [x] Std(in|out|err) without PTY
  - [ ] PTY
  - [x] Passing of environment variables
  - [ ] Return exit status codes
  - [ ] Signals
  - [ ] Specification of a command
- [ ] Authentication and executing as a specific user
  - [ ] Password validation (not hardcoded)
  - [ ] SSH keys
- Key file formats
  - [x] Something custom
  - [ ] OpenSSH keys
- [ ] Port forwarding
- [ ] SCP File Transfers

## License

    Copyright (c) 2018 Redox OS Developers

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
