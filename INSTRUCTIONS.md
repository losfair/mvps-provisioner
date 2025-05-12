# MVPS Provisioner

This is a local service written in Go that manages attachment and detachment of
`mvps`-backed virtual block devices.

## Environment variables

- `MVPS_TE_JWT_SECRET` - the secret used to sign JWTs internally.

## Starting up

When the service starts, it should immediately start `/usr/bin/mvps-te`, with:

- inherited environment variables
- `MVPS_TE_LISTEN=127.0.0.1:2192`
- `MVPS_TE_JWT_SECRET=<random 32-byte hex string>`

It then starts an SEQPACKET listener on the Unix socket provided in env var
`PROVISIONER_LISTEN_PATH`. The message format is as follows:

- byte 0-3: magic 0x6ae9a757
- byte 4: command
  - 0x01: mount
- byte 5-8: image key length
- byte 8+: image key

After receiving the message, it should lookup the provided image key, either
from a K8s ConfigMap whose name is provided in the environment variable
`PROVISIONER_IMAGES_CM` if such an env var exists, or from the local file
`./images.json` otherwise. The value is in the following format:

```json
{
  "image_id": "...",
  "image_size": 1073741824
}
```

Then, it signs a JWT using `MVPS_TE_JWT_SECRET`:

```json
{
  "image_id": "...",
  "image_size": ...,
  "page_size_bits": 12,
  "exp": 3000000000, // virtually forever
  "client_id": "static"
}
```

and starts `nbd-client`:

```bash
nbd-client -N $SIGNED_JWT 127.0.0.1 2192
```

It should get the name of the opened nbd device from stdout.

Then, it opens the nbd device, and sends the file descriptor back to the sender
PID on the unix socket.
