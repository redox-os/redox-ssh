# redox-ssh

A ssh client and server written entirely in Rust, primarily targeted at [Redox OS](http://redox-os.org).

## Features

Currently implemented features, ordered by priority:

  - [x] SSH Server
  - [ ] SSH Client
  - Key Exchange algorithms
    - [x] `curve25519-sha256` (via [rust-crypto](https://github.com/DaGenix/rust-crypto))
    - [ ] `diffie-hellman-group-exchange-sha1`
  - Public Key algorithms
    - [x] `ssh-ed25519` (via [rust-crypto](https://github.com/DaGenix/rust-crypto))
    - [ ] `ssh-rsa`
  - Encryption algorithms
    - [x] `aes256-ctr` (via [rust-crypto](https://github.com/DaGenix/rust-crypto))
    - [ ] `aes256-gcm`
  - MAC algorithms
    - [x] `hmac-sha2-256` (via [rust-crypto](https://github.com/DaGenix/rust-crypto))
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
