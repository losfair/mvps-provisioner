# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run

### Building the Service

```bash
# Build the service
go build -o mvps-provisioner
```

### Running the Service

```bash
# Set required environment variable for Unix socket path
export PROVISIONER_LISTEN_PATH=/var/run/mvps-provisioner.sock

# Run the service
./mvps-provisioner
```

### Building and Running the Example Client

```bash
# Build the example client
go build -o client ./examples/client_example.go

# Run the client (after starting the service)
./client /var/run/mvps-provisioner.sock [image_key]
```

## Architecture

MVPS Provisioner is a Go service that manages attachment and detachment of `mvps`-backed virtual block devices. The service:

1. **Starts the MVPS-TE service**: Upon startup, it launches `/usr/bin/mvps-te` with specific environment variables.

2. **Listens on Unix Socket**: Creates a SEQPACKET Unix socket at the path specified by `PROVISIONER_LISTEN_PATH`.

3. **Handles Mount Requests**: When a client sends a mount request, the service:
   - Verifies the request format (magic number, command, key length)
   - Loads image configuration for the requested key
   - Creates a signed JWT with image details
   - Starts `nbd-client` to connect to the MVPS-TE service
   - Automatically detaches the device if the client dies
   - Opens the NBD device and sends the file descriptor back to the client

4. **Key Components**:
   - Socket Communication: Uses Unix SEQPACKET sockets
   - JWT Authentication: Signs JWTs for MVPS-TE authentication
   - File Descriptor Passing: Sends open NBD device file descriptors back to clients

## Configuration

### Environment Variables

- `MVPS_TE_JWT_SECRET`: Secret for signing JWTs (optional, generates random if not provided)
- `PROVISIONER_LISTEN_PATH`: Path to the Unix socket where the service listens
- `PROVISIONER_IMAGES_CM`: (Optional) K8s ConfigMap with image configurations

### Image Configuration

Images are configured as files in the directory provided as env var `IMAGE_CONFIG_DIRECTORY`:

```json
{
    "image_id": "...",
    "image_size": 1073741824
}
```

## Client-Server Protocol

Clients send requests to the Unix socket with the following binary format:
- Bytes 0-3: Magic number (0x6ae9a757)
- Byte 4: Command (0x01 for mount)
- Bytes 5-8: Image key length
- Byte 8+: Image key string

The service responds by sending the file descriptor of the opened NBD device back to the client.