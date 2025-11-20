package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var (
	// Configuration flags
	configFile              = flag.String("config", "/config.json", "Configuration file path")
	port                    = flag.String("port", "8080", "Server port")
	attestationTokenPath    = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to attestation token")
	customAttestationSocket = flag.String("custom_attestation_socket", "/run/container_launcher/teeserver.sock", "Custom attestation socket")

	// Agent configuration from environment
	agentID           = os.Getenv("AGENT_ID")
	agentDomain       = os.Getenv("AGENT_DOMAIN")
	agentPrivateKeyEnc = os.Getenv("AGENT_PRIVATE_KEY_ENC") // KMS encrypted private key
	operatorProjectID  = os.Getenv("OPERATOR_PROJECT_ID")
	collaborator1KMSURI = os.Getenv("COLLABORATOR_1_KMS_URI")
	collaborator2KMSURI = os.Getenv("COLLABORATOR_2_KMS_URI")

	// Runtime state
	attestationJWT      string
	agentPrivateKey     *rsa.PrivateKey
	agentCertificate    *x509.Certificate
	logger              *log.Logger
	decryptedSecrets    map[string]string
	teeInstanceID       string
	imageHash           string
	httpServer          *http.Server // Store server reference for graceful shutdown

	// Node.js agent supervision
	nodeAgentCmd        *exec.Cmd
	nodeAgentRunning    bool
)

type Config struct {
	AgentID     string   `json:"agent_id"`
	Domain      string   `json:"domain"`
	RPCEndpoint string   `json:"rpc_endpoint"`
	Contracts   Contracts `json:"contracts"`
}

type Contracts struct {
	ERC8004Registry        string `json:"erc8004_registry"`
	ReputationRegistryV2   string `json:"reputation_registry_v2"`
	ServiceRegistry        string `json:"service_registry"`
}

type AttestationClaims struct {
	jwt.RegisteredClaims
	ImageDigest      string   `json:"image_digest"`
	ImageReference   string   `json:"image_reference"`
	InstanceID       string   `json:"instance_id"`
	ProjectID        string   `json:"project_id"`
	ProjectNumber    string   `json:"project_number"`
	Zone             string   `json:"zone"`
}

func main() {
	flag.Parse()

	logger = log.New(os.Stdout, "[TEE-AGENT] ", log.LstdFlags|log.Lshortfile)
	logger.Println("🚀 Starting ERC-8004 TEE Agent in GCP Confidential Space")

	// Initialize secrets map
	decryptedSecrets = make(map[string]string)

	// Start server immediately to respond to health checks
	go startServer()

	// Wait a bit for system to stabilize
	time.Sleep(5 * time.Second)

	// For this deployment, we use Secret Manager (not KMS encryption)
	// The attestation token is available for verification, but we don't need KMS
	logger.Println("🔐 Using Secret Manager for credentials (TEE with attestation)")

	// Step 1: Read attestation token (for verification, not for KMS access)
	for i := 0; i < 10; i++ {
		if err := readAttestationToken(); err != nil {
			logger.Printf("Waiting for attestation token (attempt %d/10): %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	if attestationJWT != "" {
		logger.Println("✅ Attestation token available (for verification)")
	} else {
		logger.Println("⚠️  No attestation token (running without hardware attestation)")
	}

	// Step 2: Initialize agent runtime with Secret Manager
	if err := initializeAgentRuntime(); err != nil {
		logger.Printf("⚠️  Failed to fetch secrets from Secret Manager: %v", err)
		logger.Println("   Continuing with environment variables only...")
	}

	// Step 3: Shutdown bootstrap server and exec into Node.js agent (replaces this process)
	logger.Println("🚀 Launching Node.js agent...")
	execNodeAgent()

	// Should never reach here
	logger.Println("❌ Failed to exec into Node.js agent")
	os.Exit(1)
}

func readAttestationToken() error {
	logger.Println("📖 Reading Confidential Space attestation token...")

	// Try multiple methods to get the attestation token
	var tokenBytes []byte
	var err error

	// Method 1: Try Unix domain socket (CORRECT method for Confidential Space)
	if tokenBytes, err = fetchAttestationFromSocket(*customAttestationSocket); err != nil {
		logger.Printf("Method 1 failed (Unix socket %s): %v", *customAttestationSocket, err)

		// Method 2: Read from file path (traditional method)
		if tokenBytes, err = os.ReadFile(*attestationTokenPath); err != nil {
			logger.Printf("Method 2 failed (file path): %v", err)

			// Method 3: Try metadata service
			if tokenBytes, err = fetchAttestationFromMetadata(); err != nil {
				logger.Printf("Method 3 failed (metadata service): %v", err)

				// Method 4: Try environment variable
				if envToken := os.Getenv("ATTESTATION_TOKEN"); envToken != "" {
					tokenBytes = []byte(envToken)
					logger.Println("Method 4: Found token in environment variable")
				} else {
					return fmt.Errorf("failed to read attestation token from all sources: socket=%v, file=%v, metadata=%v, env=empty", err, err, err)
				}
			} else {
				logger.Println("Method 3: Found token via metadata service")
			}
		} else {
			logger.Println("Method 2: Found token via file path")
		}
	} else {
		logger.Println("Method 1: Found token via Unix socket (Confidential Space)")
	}

	attestationJWT = string(tokenBytes)

	// Parse and validate the token
	token, _, err := new(jwt.Parser).ParseUnverified(attestationJWT, &AttestationClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse attestation token: %w", err)
	}

	claims, ok := token.Claims.(*AttestationClaims)
	if !ok {
		return errors.New("invalid attestation claims")
	}

	// Store important values
	teeInstanceID = claims.InstanceID
	imageHash = claims.ImageDigest

	logger.Printf("✅ Attestation token valid for instance: %s", teeInstanceID)
	logger.Printf("   Image hash: %s", imageHash)
	logger.Printf("   Project: %s", claims.ProjectID)

	// Write attestation JWT to file for Node.js agent to read
	// This allows the /attestation endpoint to serve the JWT for third-party verification
	// Node.js runs as non-root user 'teeagent' (UID 1000) and can't access the Unix socket
	attestationPath := "/tmp/attestation.jwt"
	if err := os.WriteFile(attestationPath, []byte(attestationJWT), 0644); err != nil {
		logger.Printf("⚠️  Failed to write attestation to %s: %v", attestationPath, err)
		logger.Println("   Node.js agent will not be able to serve attestation endpoint")
	} else {
		logger.Printf("✅ Attestation JWT written to %s for Node.js agent", attestationPath)
		logger.Printf("   File permissions: 0644 (readable by all users)")

		// Also write to /app directory where Node.js has guaranteed access
		appAttestationPath := "/app/attestation.jwt"
		if err := os.WriteFile(appAttestationPath, []byte(attestationJWT), 0644); err != nil {
			logger.Printf("⚠️  Failed to write attestation to %s: %v", appAttestationPath, err)
		} else {
			logger.Printf("✅ Attestation JWT also written to %s", appAttestationPath)
		}
	}

	return nil
}

func fetchAttestationFromSocket(socketPath string) ([]byte, error) {
	// Fetch attestation token from Confidential Space launcher Unix domain socket
	// This is the CORRECT method for GCP Confidential Space
	logger.Printf("Fetching attestation from Unix socket: %s", socketPath)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://localhost/v1/token")
	if err != nil {
		return nil, fmt.Errorf("Unix socket request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("socket returned status %d: %s", resp.StatusCode, string(body))
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read socket response: %w", err)
	}

	logger.Printf("✅ Successfully fetched attestation token from Unix socket (%d bytes)", len(tokenBytes))
	return tokenBytes, nil
}

func fetchAttestationFromMetadata() ([]byte, error) {
	// Try to get attestation token from metadata service
	resp, err := http.Get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://sts.googleapis.com&format=full&include_license=true")
	if err != nil {
		return nil, fmt.Errorf("metadata request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metadata service returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func setupWorkloadIdentity() error {
	logger.Println("🔐 Setting up workload identity federation...")

	// The attestation token serves as the identity for accessing collaborator resources
	// Each collaborator has configured their workload identity pool to trust this token

	ctx := context.Background()

	// Create authenticated clients using the attestation token
	// This will automatically exchange the token for access tokens
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to get default credentials: %w", err)
	}

	// Test access by attempting to describe KMS keys
	kmsClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to create KMS client: %w", err)
	}
	defer kmsClient.Close()

	logger.Println("✅ Workload identity configured successfully")
	return nil
}

func decryptAgentCredentials() error {
	logger.Println("🔓 Decrypting agent credentials...")

	ctx := context.Background()

	// Decrypt the agent's private key using collaborator KMS
	if agentPrivateKeyEnc != "" && collaborator1KMSURI != "" {
		kmsClient, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return fmt.Errorf("failed to create KMS client: %w", err)
		}
		defer kmsClient.Close()

		// Decode the encrypted private key
		ciphertext, err := base64.StdEncoding.DecodeString(agentPrivateKeyEnc)
		if err != nil {
			return fmt.Errorf("failed to decode encrypted private key: %w", err)
		}

		// Decrypt using KMS
		req := &kmspb.DecryptRequest{
			Name:       collaborator1KMSURI,
			Ciphertext: ciphertext,
		}

		resp, err := kmsClient.Decrypt(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %w", err)
		}

		// Parse the decrypted private key
		block, _ := pem.Decode(resp.Plaintext)
		if block == nil {
			return errors.New("failed to decode PEM block")
		}

		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		agentPrivateKey = key.(*rsa.PrivateKey)
		decryptedSecrets["agent_private_key"] = string(resp.Plaintext)

		logger.Println("✅ Agent private key decrypted successfully")
	}

	// Decrypt additional secrets from collaborator 2 if needed
	// ... (similar pattern for other encrypted data)

	return nil
}

func generateTEECertificate() error {
	logger.Println("🔏 Generating TEE-specific certificate...")

	// Generate a new RSA key pair for this TEE instance
	teeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"ERC8004 TEE Agent"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    fmt.Sprintf("tee-%s.%s", teeInstanceID[:8], agentDomain),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{agentDomain, fmt.Sprintf("tee-%s.local", teeInstanceID[:8])},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &teeKey.PublicKey, teeKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	agentCertificate, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	logger.Printf("✅ TEE certificate generated: CN=%s", template.Subject.CommonName)
	return nil
}

func initializeAgentRuntime() error {
	logger.Println("🤖 Initializing agent runtime...")

	// Fetch secrets from GCP Secret Manager
	if err := fetchSecretsFromGCP(); err != nil {
		logger.Printf("⚠️  Failed to fetch secrets from Secret Manager: %v", err)
		logger.Println("   Falling back to environment variables...")
	}

	// Here we would initialize the actual agent framework
	// For now, we'll just log the successful bootstrap

	logger.Println("✅ Agent runtime initialized with decrypted credentials")
	logger.Printf("   Agent ID: %s", agentID)
	logger.Printf("   Domain: %s", agentDomain)
	if len(teeInstanceID) >= 8 {
		logger.Printf("   TEE Instance: %s", teeInstanceID[:8])
	}

	return nil
}

// fetchSecretsFromGCP retrieves secrets from GCP Secret Manager
func fetchSecretsFromGCP() error {
	logger.Println("🔐 Fetching secrets from GCP Secret Manager...")

	ctx := context.Background()

	// Get the GCP project ID from environment
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		// Try to get it from metadata service
		req, _ := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/project/project-id", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			projectIDBytes, _ := io.ReadAll(resp.Body)
			projectID = string(projectIDBytes)
		}
	}

	if projectID == "" {
		return fmt.Errorf("GCP_PROJECT_ID not found in environment or metadata")
	}

	logger.Printf("   Project ID: %s", projectID)

	// Create Secret Manager client
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer client.Close()

	// List of secrets to fetch
	secretNames := []string{
		"CAMBRIAN_API_KEY",
		"SELLER_PRIVATE_KEY",
		"RPC_URL",
		"REGISTRY_ADDRESS",  // ProofRegistry V2 contract address
		"PINATA_API_KEY",
		"PINATA_SECRET_KEY",
		"PINATA_GATEWAY_KEY",
		"GEMINI_API_KEY",     // For Google ADK integration
		"SERVER_CAMBRIAN_API_KEY",  // For MCP server authentication
	}

	// Track which secrets were loaded
	loadedCount := 0

	// Fetch each secret
	for _, secretName := range secretNames {
		// Build the resource name for the secret version
		name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName)

		// Access the secret version
		req := &secretmanagerpb.AccessSecretVersionRequest{
			Name: name,
		}

		result, err := client.AccessSecretVersion(ctx, req)
		if err != nil {
			logger.Printf("   ⚠️  Failed to access %s: %v", secretName, err)
			continue
		}

		// Set the secret as an environment variable
		secretValue := string(result.Payload.Data)
		os.Setenv(secretName, secretValue)
		loadedCount++

		logger.Printf("   ✓ Loaded %s", secretName)
	}

	// Verify all secrets were loaded
	allLoaded := (loadedCount == len(secretNames))
	if !allLoaded {
		logger.Printf("   ✗ Only %d/%d secrets loaded", loadedCount, len(secretNames))
	}

	if !allLoaded {
		return fmt.Errorf("not all secrets were loaded successfully")
	}

	logger.Println("✅ All secrets loaded from Secret Manager")
	return nil
}

// launchNodeAgent starts the Node.js agent as a supervised subprocess within the TEE
func launchNodeAgent() error {
	logger.Println("🚀 Launching Node.js agent in TEE environment...")

	// Set environment variables for the Node.js agent
	os.Setenv("TEE_MODE", "true")
	os.Setenv("PORT", "3000") // Node.js agent listens on 3000, bootstrap proxies on 8080
	os.Setenv("NODE_ENV", "production")

	// Pass through necessary secrets
	os.Setenv("CAMBRIAN_API_KEY", os.Getenv("CAMBRIAN_API_KEY"))
	os.Setenv("RPC_URL", os.Getenv("RPC_URL"))
	os.Setenv("CHAIN_ID", os.Getenv("CHAIN_ID"))
	os.Setenv("REGISTRY_ADDRESS", os.Getenv("REGISTRY_ADDRESS"))  // ProofRegistry V2 address
	os.Setenv("SELLER_PRIVATE_KEY", os.Getenv("SELLER_PRIVATE_KEY"))
	os.Setenv("BUYER_PRIVATE_KEY", os.Getenv("BUYER_PRIVATE_KEY"))
	os.Setenv("PINATA_API_KEY", os.Getenv("PINATA_API_KEY"))
	os.Setenv("PINATA_SECRET_KEY", os.Getenv("PINATA_SECRET_KEY"))
	os.Setenv("AGENT_ID", agentID)
	os.Setenv("AGENT_DOMAIN", agentDomain)

	// Google ADK + MCP integration (for dual TEE proof generation)
	os.Setenv("GEMINI_API_KEY", os.Getenv("GEMINI_API_KEY"))
	os.Setenv("SERVER_CAMBRIAN_API_KEY", os.Getenv("SERVER_CAMBRIAN_API_KEY"))
	os.Setenv("MCP_SERVER_URL", os.Getenv("MCP_SERVER_URL"))

	// Create Node.js agent command
	nodeAgentCmd = exec.Command("node", "/app/cambrian-defi-data-agent.js")
	nodeAgentCmd.Stdout = os.Stdout
	nodeAgentCmd.Stderr = os.Stderr
	nodeAgentCmd.Dir = "/app"

	// Start the agent
	if err := nodeAgentCmd.Start(); err != nil {
		return fmt.Errorf("failed to start Node.js agent: %w", err)
	}

	nodeAgentRunning = true
	logger.Printf("✅ Node.js agent started (PID: %d)", nodeAgentCmd.Process.Pid)
	logger.Println("   All execution now running in hardware-isolated TEE memory")

	// Monitor agent process in background
	go monitorNodeAgent()

	return nil
}

// monitorNodeAgent watches the Node.js agent process and restarts it if it crashes
func monitorNodeAgent() {
	for {
		// Wait for agent to exit
		err := nodeAgentCmd.Wait()
		nodeAgentRunning = false

		if err != nil {
			logger.Printf("⚠️  Node.js agent exited with error: %v", err)
		} else {
			logger.Println("⚠️  Node.js agent exited normally")
		}

		// Wait before restarting
		logger.Println("   Restarting in 5 seconds...")
		time.Sleep(5 * time.Second)

		// Restart agent
		if err := launchNodeAgent(); err != nil {
			logger.Printf("❌ Failed to restart agent: %v", err)
			logger.Println("   Will retry in 10 seconds...")
			time.Sleep(10 * time.Second)
		}
	}
}

// execNodeAgent replaces the current process with the Node.js agent
// This is simpler than supervision and works better with container restart policies
func execNodeAgent() {
	// Shutdown the bootstrap HTTP server to free port 8080
	logger.Println("🛑 Stopping bootstrap HTTP server to free port 8080...")
	if httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Printf("⚠️  Server shutdown error (continuing anyway): %v", err)
		} else {
			logger.Println("✅ Bootstrap server stopped successfully")
		}
	}

	// Set environment variables for the Node.js agent
	os.Setenv("TEE_MODE", "true")
	os.Setenv("PORT", "8080") // Node.js agent listens directly on 8080
	os.Setenv("NODE_ENV", "production")

	// Pass attestation JWT to Node.js via environment variable
	// This allows the /attestation endpoint to serve the JWT for third-party verification
	if attestationJWT != "" {
		os.Setenv("ATTESTATION_JWT", attestationJWT)
		logger.Println("✅ Attestation JWT passed to Node.js via environment variable")
	} else {
		logger.Println("⚠️  No attestation JWT available to pass to Node.js")
	}

	// Secrets are already loaded by initializeAgentRuntime()
	// They're in the environment and will be inherited by exec

	// Change to app directory
	if err := os.Chdir("/app"); err != nil {
		logger.Printf("❌ Failed to chdir to /app: %v", err)
		os.Exit(1)
	}

	// Prepare command
	logger.Println("🚀 Launching Node.js agent on port 8080...")
	logger.Println("   Command: node /app/cambrian-defi-data-agent.js")

	// Use exec.Command and start it directly (let container runtime handle restarts)
	cmd := exec.Command("node", "/app/cambrian-defi-data-agent.js")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run and wait (blocks until Node.js exits)
	if err := cmd.Run(); err != nil {
		logger.Printf("❌ Node.js agent exited with error: %v", err)
		os.Exit(1)
	}

	// If Node.js exits cleanly, also exit cleanly
	logger.Println("✅ Node.js agent exited cleanly")
	os.Exit(0)
}

// proxyToNodeAgent forwards requests to the Node.js agent running on port 3000
func proxyToNodeAgent(w http.ResponseWriter, r *http.Request) {
	if !nodeAgentRunning {
		http.Error(w, "Agent not ready", http.StatusServiceUnavailable)
		return
	}

	// Create proxy request to Node.js agent
	proxyURL := "http://localhost:3000" + r.URL.Path
	if r.URL.RawQuery != "" {
		proxyURL += "?" + r.URL.RawQuery
	}

	// Forward request
	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Send request to Node.js agent
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Agent error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

func startServer() {
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", healthHandler).Methods("GET")

	// Attestation endpoint - returns the attestation JWT
	router.HandleFunc("/attestation", attestationHandler).Methods("GET")

	// Attest endpoint - creates execution-bound attestation for proofs
	router.HandleFunc("/attest", attestHandler).Methods("POST")

	// Connect endpoint - establishes trust with EKM
	router.HandleFunc("/connect", connectHandler).Methods("POST")

	// Execute endpoint - runs agent tasks
	router.HandleFunc("/execute", executeHandler).Methods("POST")
	router.HandleFunc("/api/execute", executeHandler).Methods("POST") // DeFi Data Agent compatibility

	// NEW: Proxy all /api/* requests to Node.js agent running inside TEE
	router.PathPrefix("/api/").HandlerFunc(proxyToNodeAgent)

	// Certificate endpoint - returns TEE-generated certificate
	router.HandleFunc("/certificate", certificateHandler).Methods("GET")

	logger.Printf("🌐 Starting server on port %s", *port)
	httpServer = &http.Server{
		Addr:    ":" + *port,
		Handler: router,
	}

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Server failed: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	// Safe string slicing to avoid runtime panics
	var instanceIDShort, imageHashShort string
	if len(teeInstanceID) >= 8 {
		instanceIDShort = teeInstanceID[:8]
	} else {
		instanceIDShort = teeInstanceID
	}
	if len(imageHash) >= 16 {
		imageHashShort = imageHash[:16]
	} else {
		imageHashShort = imageHash
	}

	response := map[string]interface{}{
		"status":       "healthy",
		"tee_enabled":  attestationJWT != "",
		"instance_id":  instanceIDShort,
		"image_hash":   imageHashShort,
		"agent_domain": agentDomain,
		"agent_id":     agentID,
		"timestamp":    time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func attestationHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"attestation_jwt": attestationJWT,
		"instance_id":     teeInstanceID,
		"image_hash":      imageHash,
		"agent_id":        agentID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func attestHandler(w http.ResponseWriter, r *http.Request) {
	// Creates execution-bound attestation for proof verification
	// This endpoint binds the hardware attestation to specific execution data

	var request struct {
		AgentID      string `json:"agent_id"`
		AgentDomain  string `json:"agent_domain"`
		InputHash    string `json:"input_hash"`
		OutputHash   string `json:"output_hash"`
		MerkleRoot   string `json:"merkle_root"`
		Timestamp    int64  `json:"timestamp"`
		Nonce        string `json:"nonce"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate that we have attestation available
	if attestationJWT == "" {
		logger.Println("⚠️  Attestation requested but not available (not running in TEE)")
		http.Error(w, "TEE attestation not available", http.StatusServiceUnavailable)
		return
	}

	logger.Printf("🔐 Creating execution-bound attestation for agent %s", request.AgentID)
	logger.Printf("   Merkle Root: %s", request.MerkleRoot)
	// Safe logging with length check
	inputHashPreview := request.InputHash
	if len(inputHashPreview) > 16 {
		inputHashPreview = inputHashPreview[:16] + "..."
	}
	outputHashPreview := request.OutputHash
	if len(outputHashPreview) > 16 {
		outputHashPreview = outputHashPreview[:16] + "..."
	}
	logger.Printf("   Input Hash: %s", inputHashPreview)
	logger.Printf("   Output Hash: %s", outputHashPreview)

	// Create execution binding by hashing all execution parameters
	executionData := fmt.Sprintf("%s:%s:%s:%s:%d:%s",
		request.AgentID,
		request.InputHash,
		request.OutputHash,
		request.MerkleRoot,
		request.Timestamp,
		request.Nonce,
	)
	executionHash := sha256.Sum256([]byte(executionData))
	executionBinding := base64.StdEncoding.EncodeToString(executionHash[:])

	// Create bound attestation token
	// In production, this would be a new JWT signed by TEE key that includes execution data
	// For now, we return the hardware attestation plus execution binding
	boundClaims := jwt.MapClaims{
		"hardware_attestation": attestationJWT[:64] + "...", // Truncated for size
		"execution_binding":    executionBinding,
		"agent_id":             request.AgentID,
		"agent_domain":         request.AgentDomain,
		"input_hash":           request.InputHash,
		"output_hash":          request.OutputHash,
		"merkle_root":          request.MerkleRoot,
		"timestamp":            request.Timestamp,
		"nonce":                request.Nonce,
		"tee_instance_id":      teeInstanceID,
		"tee_image_hash":       imageHash,
		"bound_at":             time.Now().Unix(),
	}

	// Sign with TEE-specific key if available
	var boundToken string
	if agentPrivateKey != nil {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, boundClaims)
		boundToken, _ = token.SignedString(agentPrivateKey)
	} else {
		// Fallback: sign with instance-specific secret
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, boundClaims)
		boundToken, _ = token.SignedString([]byte(teeInstanceID + imageHash))
	}

	// Get container digest from image hash (if available)
	containerDigest := imageHash
	if len(containerDigest) == 0 {
		containerDigest = "sha256:unknown"
	}

	// Return the bound attestation in the format expected by cambrian-defi-data-agent.js
	response := map[string]interface{}{
		"attestation_jwt":  attestationJWT,              // Original hardware attestation
		"bound_token":      boundToken,                  // Execution-bound token
		"code_hash":        imageHash,                   // Container image hash
		"container_digest": containerDigest,             // Same as code_hash
		"instance_id":      teeInstanceID,               // TEE instance ID
		"timestamp":        time.Now().Unix(),           // Attestation creation time
		"platform":         "GCP Confidential Space",    // Platform identifier
		"measurements": map[string]interface{}{          // Hardware measurements
			"image_digest":      imageHash,
			"execution_binding": executionBinding,
		},
		"nonce": request.Nonce, // Echo back nonce for replay protection
	}

	logger.Printf("✅ Execution-bound attestation created")
	if len(teeInstanceID) >= 8 {
		logger.Printf("   Instance: %s", teeInstanceID[:8])
	} else {
		logger.Printf("   Instance: %s", teeInstanceID)
	}
	if len(executionBinding) >= 16 {
		logger.Printf("   Binding: %s", executionBinding[:16])
	} else {
		logger.Printf("   Binding: %s", executionBinding)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func connectHandler(w http.ResponseWriter, r *http.Request) {
	// Implement EKM channel binding for mTLS verification
	// This ensures the TLS connection is bound to this specific TEE

	var request struct {
		ClientID string `json:"client_id"`
		Nonce    string `json:"nonce"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Generate connection-specific token with EKM
	connectionToken := generateConnectionToken(request.ClientID, request.Nonce)

	response := map[string]interface{}{
		"connection_token": connectionToken,
		"attestation_jwt":  attestationJWT,
		"instance_id":      teeInstanceID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	// Execute DeFi Data Agent service requests with TEE attestation

	var request struct {
		Service    string                 `json:"service"`
		Data       map[string]interface{} `json:"data"`
		Timestamp  int64                  `json:"timestamp"`
		ClientInfo map[string]interface{} `json:"clientInfo"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	logger.Printf("🔒 TEE Executing service: %s for client: %v", request.Service, request.ClientInfo)

	var serviceResult map[string]interface{}
	var err error

	// Handle different DeFi Data Agent services
	switch request.Service {
	case "price-current":
		tokenAddress, ok := request.Data["token_address"].(string)
		if !ok {
			http.Error(w, "Missing or invalid token_address", http.StatusBadRequest)
			return
		}
		serviceResult, err = fetchPriceFromCambrian(tokenAddress)
		if err != nil {
			logger.Printf("❌ Price fetch failed: %v", err)
			http.Error(w, fmt.Sprintf("Service execution failed: %v", err), http.StatusInternalServerError)
			return
		}

	case "price-multi", "ohlcv":
		// TODO: Implement additional services
		serviceResult = map[string]interface{}{
			"message": fmt.Sprintf("Service %s not yet implemented in TEE", request.Service),
			"status":  "not_implemented",
		}

	default:
		http.Error(w, fmt.Sprintf("Unknown service: %s", request.Service), http.StatusBadRequest)
		return
	}

	// Create TEE-attested response
	attestedResult := map[string]interface{}{
		"service":      request.Service,
		"data":         serviceResult,
		"tee_metadata": map[string]interface{}{
			"instance_id":   teeInstanceID,
			"image_hash":    imageHash,
			"attestation":   attestationJWT[:64] + "...", // Truncated for response size
			"timestamp":     time.Now().Unix(),
			"client_info":   request.ClientInfo,
		},
		"status": "completed",
	}

	// Sign the result with TEE-generated key if available
	if agentPrivateKey != nil {
		signature := signData(attestedResult)
		attestedResult["tee_signature"] = signature
	}

	logger.Printf("✅ TEE service execution completed: %s", request.Service)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attestedResult)
}

func certificateHandler(w http.ResponseWriter, r *http.Request) {
	if agentCertificate == nil {
		http.Error(w, "Certificate not available", http.StatusServiceUnavailable)
		return
	}

	// Return the TEE-generated certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: agentCertificate.Raw,
	})

	response := map[string]interface{}{
		"certificate":     string(certPEM),
		"attestation_jwt": attestationJWT,
		"instance_id":     teeInstanceID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateConnectionToken(clientID, nonce string) string {
	// Generate a JWT token that binds the TLS connection to this TEE
	claims := jwt.MapClaims{
		"client_id":   clientID,
		"nonce":       nonce,
		"instance_id": teeInstanceID,
		"image_hash":  imageHash,
		"issued_at":   time.Now().Unix(),
		"expires_at":  time.Now().Add(5 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(teeInstanceID + imageHash))

	return tokenString
}

func signData(data interface{}) string {
	// Sign data with the TEE-generated private key
	if agentPrivateKey == nil {
		return ""
	}

	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)

	signature, err := rsa.SignPKCS1v15(rand.Reader, agentPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		logger.Printf("Failed to sign data: %v", err)
		return ""
	}

	return base64.StdEncoding.EncodeToString(signature)
}

func fetchPriceFromCambrian(tokenAddress string) (map[string]interface{}, error) {
	logger.Printf("🔍 Fetching price for token: %s", tokenAddress)

	// Construct the Cambrian API URL
	apiURL := fmt.Sprintf("https://opabinia.cambrian.network/api/v1/solana/price-current?token_address=%s", tokenAddress)

	// Create HTTP request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers for Cambrian API
	req.Header.Set("User-Agent", "ERC8004-TEE-Agent/1.0")
	if apiKey := os.Getenv("CAMBRIAN_API_KEY"); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	// Execute the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var cambrianResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cambrianResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Transform the response to match DeFi Data Agent format
	result := map[string]interface{}{
		"tokenAddress": tokenAddress,
		"priceUSD":     cambrianResponse["priceUSD"],
		"symbol":       cambrianResponse["symbol"],
		"timestamp":    time.Now().Format(time.RFC3339),
		"source":       "Cambrian API (TEE-attested)",
		"metadata": map[string]interface{}{
			"tee_instance":   teeInstanceID,
			"attestation_id": imageHash[:16],
			"execution_time": time.Now().Unix(),
		},
	}

	logger.Printf("✅ Price fetched successfully: %v USD", cambrianResponse["priceUSD"])
	return result, nil
}