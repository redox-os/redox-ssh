# redox-ssh

A ssh client and server written entirely on rust, primarily targeted at [Redox OS](http://redox-os.org).

## Features

Currently implemented features, ordered by priority:

  - [x] SSH Server
  - [ ] SSH Client
  - Key Exchange algorithms
    - [ ] `diffie-hellman-group-exchange-sha1`
    - [x] `curve25519-sha256`
  - Public Key algorithms
    - [ ] `ssh-rsa`
    - [x] `ssh-ed25519`
  - Encryption algorithms
    - [x] `aes256-ctr`
    - [ ] `aes256-gcm`
  - MAC algorithms
    - [x] `hmac-sha2-256`
  - [ ] Port forwarding
  - [ ] SCP File Transfers

## License

    Redox SSH
    Copyright (C) 2017  Thomas Gatzweiler

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
