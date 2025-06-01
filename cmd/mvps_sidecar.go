package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const SOCKET_PATH = "/var/run/mvps-provisioner/mvps-provisioner.sock"

func createMessage(imageKey string) []byte {
	magic := uint32(0x6ae9a757)
	command := uint8(0x01)
	keyBytes := []byte(imageKey)
	keyLength := uint32(len(keyBytes))

	// Calculate total message size
	messageSize := 4 + 1 + 4 + len(keyBytes) // magic + command + length + key
	message := make([]byte, messageSize)

	// Pack the message using little endian format
	binary.LittleEndian.PutUint32(message[0:4], magic)
	message[4] = command
	binary.LittleEndian.PutUint32(message[5:9], keyLength)
	copy(message[9:], keyBytes)

	return message
}

func sendFdsAndWaitOK(conn *net.UnixConn, mountpoint, imageKey string) error {
	// Open mount namespace fd
	mntNsFd, err := syscall.Open("/proc/self/ns/mnt", syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open mount namespace: %v", err)
	}
	defer syscall.Close(mntNsFd)

	// Create mountpoint directory if it doesn't exist
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		return fmt.Errorf("failed to create mountpoint directory: %v", err)
	}

	// Open mountpoint directory fd
	mountpointDirFd, err := syscall.Open(mountpoint, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open mountpoint directory: %v", err)
	}
	defer syscall.Close(mountpointDirFd)

	// Create and send the message with file descriptors
	message := createMessage(imageKey)
	fds := []int{mntNsFd, mountpointDirFd}

	// Send message with file descriptors using sendmsg
	err = sendMessageWithFds(conn, message, fds)
	if err != nil {
		return fmt.Errorf("failed to send message with fds: %v", err)
	}

	// Wait for "OK" response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if string(response[:n]) != "OK" {
		return fmt.Errorf("unexpected response: %s", string(response[:n]))
	}

	return nil
}

func sendMessageWithFds(conn *net.UnixConn, message []byte, fds []int) error {
	// Get the underlying file descriptor
	connFile, err := conn.File()
	if err != nil {
		return err
	}
	defer connFile.Close()

	fd := int(connFile.Fd())

	// Prepare control message for file descriptors
	controlMsg := syscall.UnixRights(fds...)

	// Send message with file descriptors
	err = syscall.Sendmsg(fd, message, controlMsg, nil, 0)
	if err != nil {
		return err
	}

	return nil
}

func handleSignal(sigChan chan os.Signal) {
	sig := <-sigChan
	fmt.Printf("Received signal %v, exiting...\n", sig)
	os.Exit(0)
}

func main() {
	// Get image_key and mountpoint from environment variables
	imageKey := os.Getenv("IMAGE_KEY")
	if imageKey == "" {
		fmt.Fprintln(os.Stderr, "Error: IMAGE_KEY environment variable not set")
		os.Exit(1)
	}

	mountpoint := os.Getenv("MOUNTPOINT")
	if mountpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: MOUNTPOINT environment variable not set")
		os.Exit(1)
	}

	// Register signal handlers for graceful termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	go handleSignal(sigChan)

	// Create a UNIX socket of type SOCK_SEQPACKET
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: SOCKET_PATH, Net: "unixpacket"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send message with fds and wait for OK
	err = sendFdsAndWaitOK(conn, mountpoint, imageKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Keep the script alive and the connection open
	fmt.Println("Connection established. Keeping connection alive...")
	for {
		time.Sleep(60 * time.Second) // Sleep to reduce CPU usage while keeping the script alive
	}
}
