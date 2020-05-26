# drawpile-ldap-auth-server

[![Docker Pulls](https://img.shields.io/docker/pulls/bytewave81/drawpile-ldap-auth-server)][docker-hub-repo]
[![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/bytewave81/drawpile-ldap-auth-server)][docker-hub-repo]

> A Drawpile-compatible auth server backed by LDAP

## Table of Contents

- [Background](#background)
- [Install](#install)
  - [Prerequisites](#prerequisites)
  - [Docker](#docker)
  - [Manual](#manual)
- [Usage](#usage)
  - [Configuring Drawpile](#configuring-drawpile)
  - [Configuring the auth server](#configuring-the-auth-server)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Background

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
; PUBLIC key for token signing, see below
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

## Maintainers

- [Eliot Partridge](https://github.com/BytewaveMLP)

## Contribute

PRs, feature suggestions, and bug reports welcome.

## License

Copyright (c) Eliot Partridge, 2020. Licensed under [the MIT License](/LICENSE).

[docker-hub-repo]: https://hub.docker.com/r/bytewave81/drawpile-ldap-auth-server
