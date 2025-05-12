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
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <socket_path> <image_key>\n", os.Args[0])
		os.Exit(1)
	}

	socketPath := os.Args[1]
	imageKey := os.Args[2]

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

	// Send the message
	_, err = conn.Write(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send message: %v\n", err)
		os.Exit(1)
	}

	// Receive the file descriptor
	buf := make([]byte, 16)
	oob := make([]byte, 32)
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to receive message: %v\n", err)
		os.Exit(1)
	}

	if n > 0 {
		fmt.Printf("Received message: %s\n", string(buf[:n]))
	}

	// Extract the file descriptor
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse socket control message: %v\n", err)
		os.Exit(1)
	}

	if len(scms) > 0 {
		fds, err := syscall.ParseUnixRights(&scms[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse Unix rights: %v\n", err)
			os.Exit(1)
		}

		if len(fds) > 0 {
			fmt.Printf("Received file descriptor: %d\n", fds[0])
			// Create a new file from the file descriptor
			nbdFile := os.NewFile(uintptr(fds[0]), "nbd")
			if nbdFile != nil {
				fmt.Println("Successfully received NBD device file descriptor")
				// You can now use nbdFile for read/write operations
				// Don't close it here as it would detach the NBD device
				// Keep it open for as long as you need the device
			}
		}
	}

	// Wait for user input to keep the process running (and NBD device attached)
	fmt.Println("Press Enter to exit and detach NBD device...")
	fmt.Scanln()
}