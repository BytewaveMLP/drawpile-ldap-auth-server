# drawpile-ldap-auth-server

[![Docker Pulls](https://img.shields.io/docker/pulls/bytewave81/drawpile-ldap-auth-server)][docker-hub-repo]
[![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/bytewave81/drawpile-ldap-auth-server)][docker-hub-repo]

> A Drawpile-compatible auth server backed by LDAP

## Table of Contents

- [Install](#install)
  - [Prerequisites](#prerequisites)
  - [Docker](#docker)
  - [Manual](#manual)
- [Usage](#usage)
  - [Configuring Drawpile](#configuring-drawpile)
  - [Configuring the auth server](#configuring-the-auth-server)
    - [Generating a token keypair](#generating-a-token-keypair)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

### Prerequisites

- Node.js v12 or greater
- An LDAP server
- A Drawpile server configured for external authentication

### Docker

See [`docker-compose.yml`](/docker-compose.yml) for an example Compose file. Alternatively, you may want to use `docker run`:

```shell
$ cp config.example.toml config.toml
$ $EDITOR config.toml # see README.md "Configuring the auth server" for details
$ docker run -d --rm \
    -p 8081:8081 \
    -v path/to/config.toml:/usr/src/app/config.toml:ro
    bytewave81/drawpile-ldap-auth-server
```

### Manual

You don't want to use my shiny Docker setup? But I worked so hard on it!

```shell
$ git clone https://github.com/BytewaveMLP/drawpile-ldap-auth-server.git
$ cd drawpile-ldap-auth-server
$ yarn install
$ yarn build
$ cp config.example.toml config.toml
$ $EDITOR config.toml # see README.md "Configuring the auth server" for details
$ node .
```

## Usage

### Configuring Drawpile

In order to make use of this, you need to configure Drawpile to look for your external auth server. Note that both Drawpile and clients will need access to the auth server, so drawpile-ldap-auth-server *must* be internet-facing. I recommend putting this behind nginx in order to allow secure communications between clients and the server.

To configure Drawpile to direct clients to this auth server, add the following entries to the `[config]` section of your Drawpile instance:

```ini
; enable extauth and direct users to the auth server
extauth = true
; PUBLIC key for token signing, see "Generating a token keypair"
extauthkey = ""
; users must be in this LDAP group in order to user the instance (optional)
extauthgroup = user
; don't fall back to the internal user database if the auth server is unreachable
extauthfallback = false
; drawpile-ldap-auth-server can pull moderator status from LDAP groups; set this
; to true if you'd like to enable that
extauthmod = true
; should guests be allowed to access Drawpile?
; this setting must match the setting in config.toml for drawpile-ldap-auth-server
allowGuests = false
; should guests be allowed to host sessions?
allowGuestHosts = false
```

Additionally, you need to pass the `--extauth` parameter to `drawpile-srv` which points to the **public-facing** URL for your drawpile-ldap-auth-server instance.

### Configuring the auth server

First, copy `config.example.toml` to `config.toml`. Then, open it in your favorite editor. Each config option is explained rather clearly in the config comments.

For more details on TOML syntax, see [the README](https://github.com/toml-lang/toml#user-content-example).

Additionally, there are a few environment variables which may be used:

- `DRAWPILE_AUTH_TOKEN_SIGNING_KEY`
  
  The private Ed25519 key for Drawpile auth tokens. See ["Generating a token keypair"](#generating-a-token-keypair) below for instructions to generate this. Setting this value in the environment overrides the value in `config.toml`.

- `LOG_LEVEL`

  The [Winston log level](https://github.com/winstonjs/winston#logging-levels) to use. By default, this is `info` if `NODE_ENV` is `production`, and `debug` otherwise. It's probably best to leave this as the default; setting this to anything below `debug` may expose sensitive information in your logs, and should only be used for debugging.

- `NODE_ENV`

  The environment this instance is running under. By default, this is assumed to be `development`, in which case debug-level logging output is enabled (unless overridden via `LOG_LEVEL`). Set this to `production` in an actual deployment (the Docker image does this for you).

#### Generating a token keypair

Drawpile uses libsodium to handle token verification, which expects a "raw" format Ed25519 public key (ie, no container format). However, OpenSSL (and therefore Node) operate on containerized keys using DER and PEM formats. As such, you will need to generate your keypair in a very specific manner.

```shell
# generate private key; this goes in config.toml or in your environment as DRAWPILE_AUTH_TOKEN_SIGNING_KEY
$ PRIVKEY="$(openssl genpkey -algorithm ed25519 -outform DER | openssl base64)"; echo $PRIVKEY
# generate public key; this goes in your Drawpile config.ini
$ echo "$PRIVKEY" | openssl base64 -d | openssl pkey -inform DER -outform DER -pubout | tail -c +13 | openssl base64
```

## Maintainers

- [Eliot Partridge](https://github.com/BytewaveMLP)

## Contribute

PRs, feature suggestions, and bug reports welcome.

## License

Copyright (c) Eliot Partridge, 2020. Licensed under [the MIT License](/LICENSE).

[docker-hub-repo]: https://hub.docker.com/r/bytewave81/drawpile-ldap-auth-server
