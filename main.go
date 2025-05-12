package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	MagicNum = uint32(0x6ae9a757)
	CmdMount = byte(0x01)
	JwtExp   = int64(3000000000) // virtually forever
	ClientId = "static"
	PageBits = 12
	MvpsAddr = "127.0.0.1:2192"
)

type ImageConfig struct {
	ImageID   string `json:"image_id"`
	ImageSize int64  `json:"image_size"`
}

type JWTClaims struct {
	ImageID      string `json:"image_id"`
	ImageSize    int64  `json:"image_size"`
	PageSizeBits int    `json:"page_size_bits"`
	ClientID     string `json:"client_id"`
	jwt.RegisteredClaims
}

func generateRandomHexString(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func loadImageConfig(imageKey string) (*ImageConfig, error) {
	var configPath string
	if cm := os.Getenv("IMAGE_CONFIG_DIRECTORY"); cm != "" {
		configPath = filepath.Join(cm, imageKey)
	} else {
		return nil, fmt.Errorf("IMAGE_CONFIG_DIRECTORY environment variable not set")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read image config: %w", err)
	}

	var config ImageConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse image config: %w", err)
	}

	return &config, nil
}

func startMvpsTE() (*exec.Cmd, string, error) {
	// Generate random JWT secret if not provided
	jwtSecret := os.Getenv("MVPS_TE_JWT_SECRET")
	if jwtSecret == "" {
		var err error
		jwtSecret, err = generateRandomHexString(64) // 32 bytes = 64 hex chars
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate JWT secret: %w", err)
		}
	}

	// Start mvps-te process
	cmd := exec.Command("mvps-te")
	cmd.Env = append(os.Environ(),
		"MVPS_TE_LISTEN="+MvpsAddr,
		"MVPS_TE_JWT_SECRET="+jwtSecret)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}

	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("failed to start mvps-te: %w", err)
	}

	// Give mvps-te some time to start up
	time.Sleep(1 * time.Second)

	return cmd, jwtSecret, nil
}

func createSignedJWT(jwtSecret string, config *ImageConfig) (string, error) {
	key := []byte(jwtSecret)

	claims := JWTClaims{
		ImageID:      config.ImageID,
		ImageSize:    config.ImageSize,
		PageSizeBits: PageBits,
		ClientID:     ClientId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(JwtExp, 0)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}

func startNbdClient(signedJWT string) (string, error) {
	// Start nbd-client and capture its output
	cmd := exec.Command("nbd-client", "-N", signedJWT, "127.0.0.1", "2192")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start nbd-client: %w", err)
	}

	// Read nbd device name from stdout
	output, err := io.ReadAll(stdout)
	if err != nil {
		return "", fmt.Errorf("failed to read nbd-client output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("nbd-client command failed: %w", err)
	}

	// Parse the output to get the nbd device name
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "/dev/nbd") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasPrefix(field, "/dev/nbd") {
					return field, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find nbd device in output: %s", outputStr)
}

// detachStatus maintains tracking of device detachment status
type detachStatus struct {
	detached atomic.Bool
}

// newDetachStatus creates a new detachment status tracker
func newDetachStatus() *detachStatus {
	return &detachStatus{}
}

// activeDevices keeps track of all active NBD devices
var activeDevices = struct {
	sync.RWMutex
	devices map[string]*detachStatus
}{
	devices: make(map[string]*detachStatus),
}

// registerDevice adds a device to the active devices map
func registerDevice(nbdDevice string, status *detachStatus) {
	activeDevices.Lock()
	defer activeDevices.Unlock()
	activeDevices.devices[nbdDevice] = status
}

// unregisterDevice removes a device from the active devices map
func unregisterDevice(nbdDevice string) {
	activeDevices.Lock()
	defer activeDevices.Unlock()
	delete(activeDevices.devices, nbdDevice)
}

// detachAllDevices detaches all active NBD devices
func detachAllDevices() {
	activeDevices.RLock()
	devices := make(map[string]*detachStatus)
	for device, status := range activeDevices.devices {
		devices[device] = status
	}
	activeDevices.RUnlock()

	log.Printf("Detaching %d NBD devices for graceful shutdown", len(devices))
	for device, status := range devices {
		detachNbdDevice(device, status)
	}
}

// detachNbdDevice detaches an NBD device if it has not already been detached
func detachNbdDevice(nbdDevice string, status *detachStatus) {
	// Use CompareAndSwap to ensure only one detachment happens
	// If detached is already true, return immediately
	if !status.detached.CompareAndSwap(false, true) {
		// Already detached
		return
	}

	cmd := exec.Command("nbd-client", "-d", nbdDevice)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to detach NBD device: %v", err)
	} else {
		log.Printf("Successfully detached %s", nbdDevice)
	}

	// Remove from active devices map
	unregisterDevice(nbdDevice)
}

func openNbdDevice(devicePath string) (*os.File, error) {
	return os.OpenFile(devicePath, os.O_RDWR, 0)
}

func handleConnection(conn *net.UnixConn, jwtSecret string) {
	defer conn.Close()

	buf := make([]byte, 4096)
	oobBuf := make([]byte, 4096)
	n, _, _, _, err := conn.ReadMsgUnix(buf, oobBuf)
	if err != nil {
		log.Printf("Error reading from socket: %v", err)
		return
	}

	if n < 9 { // Magic (4) + Command (1) + Key Length (4)
		log.Printf("Received message too short")
		return
	}

	// Parse message
	// Check magic
	magic := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	if magic != MagicNum {
		log.Printf("Invalid magic: %x", magic)
		return
	}

	// Check command
	cmd := buf[4]
	if cmd != CmdMount {
		log.Printf("Unsupported command: %x", cmd)
		return
	}

	// Get image key length and key
	keyLen := uint32(buf[5]) | uint32(buf[6])<<8 | uint32(buf[7])<<16 | uint32(buf[8])<<24
	if n < int(9+keyLen) {
		log.Printf("Key length exceeds message size")
		return
	}
	imageKey := string(buf[9 : 9+keyLen])

	// Load image config
	config, err := loadImageConfig(imageKey)
	if err != nil {
		log.Printf("Failed to load image config for key %s: %v", imageKey, err)
		return
	}

	// Sign JWT
	signedJWT, err := createSignedJWT(jwtSecret, config)
	if err != nil {
		log.Printf("Failed to create signed JWT: %v", err)
		return
	}

	// Start nbd-client
	nbdDevice, err := startNbdClient(signedJWT)
	if err != nil {
		log.Printf("Failed to start nbd-client: %v", err)
		return
	}
	log.Printf("Successfully connected NBD device: %s", nbdDevice)

	// Create a detachment status tracker
	detachTracker := newDetachStatus()

	// Register the device in the active devices map
	registerDevice(nbdDevice, detachTracker)

	// Open NBD device
	nbdFile, err := openNbdDevice(nbdDevice)
	if err != nil {
		log.Printf("Failed to open NBD device: %v", err)
		detachNbdDevice(nbdDevice, detachTracker)
		return
	}
	defer nbdFile.Close()
	log.Printf("Opened NBD device file descriptor: %d", nbdFile.Fd())

	// Send file descriptor back on the duplicated connection
	rights := syscall.UnixRights(int(nbdFile.Fd()))
	_, _, err = conn.WriteMsgUnix([]byte("OK"), rights, nil)
	if err != nil {
		log.Printf("Failed to send NBD device file descriptor: %v", err)
		detachNbdDevice(nbdDevice, detachTracker)
		return
	}

	log.Printf("Successfully sent NBD device file descriptor for %s", nbdDevice)

	// Detach the device when the connection is closed
	_, _, _, _, _ = conn.ReadMsgUnix(buf, oobBuf)
	detachNbdDevice(nbdDevice, detachTracker)
	log.Printf("Connection closed, detaching NBD device %s", nbdDevice)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting mvps-provisioner")

	shutdownChan := make(chan struct{}, 1)
	// Start mvps-te
	mvpsCmd, jwtSecret, err := startMvpsTE()
	if err != nil {
		log.Fatalf("Failed to start mvps-te: %v", err)
	}
	log.Println("Started mvps-te")

	// Start a goroutine to monitor the mvps-te process
	// This will exit the main process if mvps-te exits
	go func() {
		err := mvpsCmd.Wait()
		if err != nil {
			log.Printf("mvps-te process exited with error: %v", err)
		} else {
			log.Printf("mvps-te process exited normally")
		}
		select {
		case shutdownChan <- struct{}{}:
		default:
		}
	}()

	// Get socket path from env
	socketPath := os.Getenv("PROVISIONER_LISTEN_PATH")
	if socketPath == "" {
		log.Fatalf("PROVISIONER_LISTEN_PATH environment variable not set")
	}

	// Remove existing socket if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			log.Fatalf("Failed to remove existing socket: %v", err)
		}
	}

	// Create SEQPACKET Unix socket
	addr := &net.UnixAddr{Name: socketPath, Net: "unixpacket"}
	listener, err := net.ListenUnix("unixpacket", addr)
	if err != nil {
		log.Fatalf("Failed to listen on socket: %v", err)
	}
	defer listener.Close()

	// Set appropriate permissions on socket
	if err := os.Chmod(socketPath, 0666); err != nil {
		log.Fatalf("Failed to set socket permissions: %v", err)
	}

	log.Printf("Listening on socket: %s", socketPath)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Start a goroutine to handle shutdown signals
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, performing graceful shutdown", sig)
		select {
		case shutdownChan <- struct{}{}:
		default:
		}
	}()

	go func() {
		<-shutdownChan
		listener.SetDeadline(time.Now())
	}()

	// Accept connections
outer:
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			select {
			case <-shutdownChan:
				// We're shutting down, exit the loop
				break outer
			default:
				log.Printf("Failed to accept connection: %v", err)
				break outer
			}
		}

		go handleConnection(conn, jwtSecret)
	}

	detachAllDevices()
	os.Remove(socketPath)
}
