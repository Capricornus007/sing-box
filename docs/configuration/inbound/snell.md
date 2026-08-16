---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "version": 5,
  "psk": "password",
<<<<<<< HEAD
  "multi_user_authentication": "userkey",
=======
>>>>>>> sagerNet/testing
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "obfs_mode": ""
}
```

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "version": 6,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "mode": ""
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

==Required==

The Snell protocol version, one of `5` `6`.

<<<<<<< HEAD
Version `5` supports HTTP obfuscation and QUIC Proxy Mode. Version `6` replaces
obfuscation with traffic shaping and requires 12 to 255 byte PSKs.

#### psk

Required in single-user and `userkey` multi-user modes. It must be omitted in
`psk` multi-user mode.
=======
Version `5` supports HTTP obfuscation (`obfs_mode`); version `6` replaces it
with traffic shaping (`mode`) and requires a `psk` of 12 to 255 bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.
>>>>>>> sagerNet/testing

#### users

Snell users.

<<<<<<< HEAD
With `multi_user_authentication: userkey`, each user must contain `userkey` and
must not contain `psk`. With `multi_user_authentication: psk`, each user must
contain an independent `psk` and must not contain `userkey`.

#### multi_user_authentication

Multi-user authentication mode, one of `userkey` or `psk`. Defaults to
`userkey`. This option is only valid when `users` is configured.

`psk` mode supports v5 and v6 `default` / `unshaped`. It is rejected for v6
`unsafe-raw`, where the protocol does not use the PSK cryptographically.
=======
When set, the server runs in multi-user mode: each entry has a `name` (optional, used in
logs) and a `userkey` (the user's key). The top-level `psk` remains the server key.
>>>>>>> sagerNet/testing

#### obfs_mode

==Version 5 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

<<<<<<< HEAD
TLS simple-obfs is intentionally unsupported. Use a [ShadowTLS](/configuration/inbound/shadowtls/)
inbound in front of Snell when TLS camouflage is required.

=======
>>>>>>> sagerNet/testing
#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.
