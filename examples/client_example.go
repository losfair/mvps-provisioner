package main

// This is a simple example of a client that connects to the mvps-provisioner service.
// This file is provided as an example and is not part of the main build.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
)

const (
	MAGIC     = uint32(0x6ae9a757)
	CMD_MOUNT = byte(0x01)
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <socket_path> <image_key> <mount_point>\n", os.Args[0])
		os.Exit(1)
	}

	socketPath := os.Args[1]
	imageKey := os.Args[2]
	mountPoint := os.Args[3]

	// Open the current mount namespace
	mountNsFile, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open mount namespace: %v\n", err)
		os.Exit(1)
	}
	defer mountNsFile.Close()

	// Create mount point directory if it doesn't exist
	err = os.MkdirAll(mountPoint, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create mount point directory: %v\n", err)
		os.Exit(1)
	}

	// Open the mount point directory
	dirFile, err := os.Open(mountPoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open mount point directory: %v\n", err)
		os.Exit(1)
	}
	defer dirFile.Close()

	// Connect to the Unix socket
	addr := &net.UnixAddr{Name: socketPath, Net: "unixpacket"}
	conn, err := net.DialUnix("unixpacket", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Prepare the message
	imageKeyBytes := []byte(imageKey)
	msgLen := 9 + len(imageKeyBytes)
	msg := make([]byte, msgLen)

	// Set magic
	binary.LittleEndian.PutUint32(msg[0:4], MAGIC)

	// Set command
	msg[4] = CMD_MOUNT

	// Set image key length
	binary.LittleEndian.PutUint32(msg[5:9], uint32(len(imageKeyBytes)))

	// Set image key
	copy(msg[9:], imageKeyBytes)

	// Prepare file descriptors to send
	fds := []int{int(mountNsFile.Fd()), int(dirFile.Fd())}
	rights := syscall.UnixRights(fds...)

	// Send the message with file descriptors
	_, _, err = conn.WriteMsgUnix(msg, rights, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sent mount request for image key '%s' with mount namespace fd %d and dirfd %d\n",
		imageKey, mountNsFile.Fd(), dirFile.Fd())

	// Receive response
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to receive response: %v\n", err)
		os.Exit(1)
	}

	if n > 0 {
		response := string(buf[:n])
		fmt.Printf("Received response: %s\n", response)
		if response == "OK" {
			fmt.Printf("Successfully mounted NBD device to %s\n", mountPoint)
		}
	}

	// Wait for user input to keep the mount active
	fmt.Println("Press Enter to exit and detach NBD device...")
	fmt.Scanln()
}
