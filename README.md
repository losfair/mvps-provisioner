# mvps-provisioner

A local service written in Go that manages attachment and detachment of `mvps`-backed virtual block devices.

## Overview

mvps-provisioner is responsible for starting and managing the `mvps-te` service and providing a Unix socket interface for clients to request attachment of NBD devices.

## Requirements

- Go 1.22 or later
- `mvps-te` binary available at `/usr/bin/mvps-te`
- `nbd-client` installed in the system

## Environment Variables

- `MVPS_TE_JWT_SECRET` - The secret used to sign JWTs (optional, will generate random if not provided)
- `PROVISIONER_LISTEN_PATH` - Path to the Unix socket where the service listens for requests
- `IMAGE_CONFIG_DIRECTORY` - Path to the directory containing image configurations

## Building

```bash
go build -o mvps-provisioner
```

## Running

```bash
export PROVISIONER_LISTEN_PATH=/var/run/mvps-provisioner.sock
./mvps-provisioner
```

## Protocol

The provisioner listens on a Unix SEQPACKET socket. Clients can send attachment requests with the following format:

- byte 0-3: magic 0x6ae9a757
- byte 4: command (0x01 for mount)
- byte 5-8: image key length
- byte 8+: image key

After processing the request, the provisioner will send back the file descriptor of the opened NBD device.