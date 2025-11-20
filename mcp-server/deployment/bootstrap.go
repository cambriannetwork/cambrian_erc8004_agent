package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/gorilla/mux"
)

var (
	// Configuration flags
	port                    = flag.String("port", "8081", "Server port")
	attestationTokenPath    = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to attestation token")
	customAttestationSocket = flag.String("custom_attestation_socket", "/run/container_launcher/teeserver.sock", "Custom attestation socket")

	// Runtime state
	attestationJWT   string
	logger           *log.Logger
	decryptedSecrets map[string]string
	httpServer       *http.Server
	nodeServerCmd    *exec.Cmd
	nodeServerRunning bool
)

func main() {
	flag.Parse()

	logger = log.New(os.Stdout, "[TEE-MCP] ", log.LstdFlags|log.Lshortfile)
	logger.Println("🚀 Starting TEE MCP Server in GCP Confidential Space")

	// Initialize secrets map
	decryptedSecrets = make(map[string]string)

	// Start health server immediately
	go startServer()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Read attestation token
	if err := readAttestationToken(); err != nil {
		logger.Printf("⚠️  Failed to read attestation token: %v", err)
		logger.Println("   Continuing without attestation (may be development mode)")
	} else {
		logger.Println("✅ Attestation token loaded")
		// Save attestation to /app for Node.js access
		if err := os.WriteFile("/app/attestation.jwt", []byte(attestationJWT), 0644); err != nil {
			logger.Printf("⚠️  Failed to save attestation: %v", err)
		} else {
			logger.Println("✅ Attestation saved to /app/attestation.jwt")
		}
	}

	// Fetch secrets from Secret Manager
	if err := fetchSecrets(); err != nil {
		logger.Printf("⚠️  Failed to fetch secrets: %v", err)
		logger.Println("   Server will use environment variables if available")
	}

	// Validate Cambrian API key before starting server (non-fatal)
	if err := validateCambrianAPIKey(); err != nil {
		logger.Printf("⚠️  Cambrian API key validation failed: %v", err)
		logger.Println("   Server will start anyway - validation is informational only")
	}

	// Start Node.js MCP server
	logger.Println("🔄 Starting Node.js MCP server...")
	if err := startNodeServer(); err != nil {
		logger.Fatalf("❌ Failed to start Node.js server: %v", err)
	}

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Printf("📥 Received signal: %v", sig)

	// Graceful shutdown
	logger.Println("🛑 Shutting down gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop Node.js server
	if nodeServerCmd != nil && nodeServerCmd.Process != nil {
		logger.Println("Stopping Node.js server...")
		nodeServerCmd.Process.Signal(syscall.SIGTERM)
		nodeServerCmd.Wait()
	}

	// Stop health server
	if httpServer != nil {
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("Error shutting down HTTP server: %v", err)
		}
	}

	logger.Println("✅ Shutdown complete")
}

func readAttestationToken() error {
	// Try to read from file first
	token, err := os.ReadFile(*attestationTokenPath)
	if err == nil {
		attestationJWT = string(token)
		return nil
	}

	// Try Unix socket if file doesn't exist
	logger.Println("Trying to fetch attestation from Unix socket...")
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", *customAttestationSocket)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://unix/v1/token")
	if err != nil {
		return fmt.Errorf("failed to fetch from socket: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("socket returned status %d", resp.StatusCode)
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}

	attestationJWT = string(tokenBytes)
	return nil
}

func fetchSecrets() error {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		logger.Println("⚠️  GCP_PROJECT_ID environment variable not set")
		return fmt.Errorf("GCP_PROJECT_ID not set")
	}

	logger.Printf("📦 Fetching secrets from Secret Manager (project: %s)...", projectID)

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		logger.Printf("❌ Failed to create Secret Manager client: %v", err)
		logger.Println("   This may indicate missing IAM permissions or credentials")
		return fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer client.Close()

	logger.Println("✅ Secret Manager client created successfully")

	// Secrets to fetch
	secrets := map[string]string{
		"cambrian-api-key": "SERVER_CAMBRIAN_API_KEY",
	}

	secretsFetched := 0
	for secretName, envVar := range secrets {
		secretPath := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName)
		logger.Printf("🔍 Attempting to fetch: %s", secretPath)

		req := &secretmanagerpb.AccessSecretVersionRequest{
			Name: secretPath,
		}

		result, err := client.AccessSecretVersion(ctx, req)
		if err != nil {
			logger.Printf("❌ Failed to fetch %s: %v", secretName, err)
			logger.Println("   Check that:")
			logger.Println("   1. Secret exists in Secret Manager")
			logger.Println("   2. Service account has 'secretmanager.versions.access' permission")
			logger.Println("   3. Secret name matches exactly")
			continue
		}

		decryptedSecrets[envVar] = string(result.Payload.Data)
		secretsFetched++
		logger.Printf("✅ Fetched secret: %s (length: %d chars)", secretName, len(result.Payload.Data))
		logger.Printf("   First 8 chars: %s...", string(result.Payload.Data[:min(8, len(result.Payload.Data))]))
	}

	logger.Printf("📊 Secrets fetched: %d/%d", secretsFetched, len(secrets))

	if secretsFetched == 0 {
		return fmt.Errorf("no secrets could be fetched")
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func validateCambrianAPIKey() error {
	logger.Println("🔐 Validating Cambrian API key...")

	// Get API key from decrypted secrets
	apiKey, exists := decryptedSecrets["SERVER_CAMBRIAN_API_KEY"]
	if !exists || apiKey == "" {
		return fmt.Errorf("SERVER_CAMBRIAN_API_KEY not found in secrets")
	}

	// Test API key by making a simple request to Cambrian API
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://opabinia.cambrian.network/openapi.json", nil)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate API key (network error): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("Cambrian API key is INVALID (status %d) - check Secret Manager", resp.StatusCode)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Cambrian API returned error %d during validation", resp.StatusCode)
	}

	logger.Printf("✅ Cambrian API key validated (first 8 chars: %s...)", apiKey[:8])
	return nil
}

func startNodeServer() error {
	// Check if Node.js entry point exists
	if _, err := os.Stat("/app/dist/index.js"); err != nil {
		logger.Printf("❌ /app/dist/index.js not found: %v", err)
		// List /app directory contents
		if entries, err := os.ReadDir("/app"); err == nil {
			logger.Println("📁 /app directory contents:")
			for _, entry := range entries {
				logger.Printf("  - %s", entry.Name())
			}
		}
		// List /app/dist if it exists
		if entries, err := os.ReadDir("/app/dist"); err == nil {
			logger.Println("📁 /app/dist directory contents:")
			for _, entry := range entries {
				logger.Printf("  - %s", entry.Name())
			}
		} else {
			logger.Printf("❌ /app/dist directory not found: %v", err)
		}
		return fmt.Errorf("Node.js entry point not found: %w", err)
	}

	logger.Println("✅ Found /app/dist/index.js")

	// Set up environment
	env := os.Environ()

	// Add decrypted secrets
	for key, value := range decryptedSecrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
		logger.Printf("🔑 Added secret: %s", key)
	}

	// Add TEE-specific env vars
	env = append(env, fmt.Sprintf("TEE_MODE=%s", os.Getenv("TEE_MODE")))
	env = append(env, fmt.Sprintf("CONTAINER_DIGEST=%s", os.Getenv("CONTAINER_DIGEST")))
	// Node.js listens on internal port 8082, bootstrap proxies from 8081
	env = append(env, "PORT=8082")

	logger.Printf("🔧 Starting Node.js server on port %s...", *port)

	// Capture stdout and stderr to files for debugging
	stdoutFile, err := os.Create("/app/logs/nodejs-stdout.log")
	if err != nil {
		logger.Printf("⚠️  Failed to create stdout log file: %v", err)
	}
	stderrFile, err := os.Create("/app/logs/nodejs-stderr.log")
	if err != nil {
		logger.Printf("⚠️  Failed to create stderr log file: %v", err)
	}

	// Start Node.js server
	nodeServerCmd = exec.Command("node", "/app/dist/index.js")
	nodeServerCmd.Env = env
	nodeServerCmd.Stdout = stdoutFile
	nodeServerCmd.Stderr = stderrFile

	if err := nodeServerCmd.Start(); err != nil {
		logger.Printf("❌ Failed to start Node.js: %v", err)
		return fmt.Errorf("failed to start Node.js server: %w", err)
	}

	nodeServerRunning = true
	logger.Printf("✅ Node.js MCP server started (PID: %d)", nodeServerCmd.Process.Pid)

	// Monitor Node.js server
	go func() {
		err := nodeServerCmd.Wait()
		nodeServerRunning = false
		if err != nil {
			logger.Printf("❌ Node.js server exited with error: %v", err)
		} else {
			logger.Println("Node.js server exited normally")
		}
	}()

	return nil
}

func proxyToNodeJS(w http.ResponseWriter, r *http.Request) {
	if !nodeServerRunning {
		http.Error(w, "Node.js server not running", http.StatusServiceUnavailable)
		return
	}

	// Create proxy URL
	proxyURL := fmt.Sprintf("http://localhost:8082%s", r.URL.Path)
	if r.URL.RawQuery != "" {
		proxyURL += "?" + r.URL.RawQuery
	}

	// Create proxy request
	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Make request
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
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

	// Copy body
	io.Copy(w, resp.Body)
}

func startServer() {
	router := mux.NewRouter()

	// Health endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := "initializing"
		if nodeServerRunning {
			status = "healthy"
		}

		response := map[string]interface{}{
			"status":       status,
			"service":      "cambrian-mcp-server-tee",
			"teeMode":      os.Getenv("TEE_MODE") == "true",
			"nodeServer":   nodeServerRunning,
			"attestation":  attestationJWT != "",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Logs endpoint
	router.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		stdout, _ := os.ReadFile("/app/logs/nodejs-stdout.log")
		stderr, _ := os.ReadFile("/app/logs/nodejs-stderr.log")

		response := map[string]interface{}{
			"stdout": string(stdout),
			"stderr": string(stderr),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Debug endpoint
	router.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		// List /app directory
		appContents := []string{}
		if entries, err := os.ReadDir("/app"); err == nil {
			for _, entry := range entries {
				info, _ := entry.Info()
				appContents = append(appContents, fmt.Sprintf("%s (%v bytes)", entry.Name(), info.Size()))
			}
		}

		// List /app/dist directory
		distContents := []string{}
		distError := ""
		if entries, err := os.ReadDir("/app/dist"); err == nil {
			for _, entry := range entries {
				info, _ := entry.Info()
				distContents = append(distContents, fmt.Sprintf("%s (%v bytes)", entry.Name(), info.Size()))
			}
		} else {
			distError = err.Error()
		}

		// Check if index.js exists
		indexJsExists := false
		indexJsSize := int64(0)
		if info, err := os.Stat("/app/dist/index.js"); err == nil {
			indexJsExists = true
			indexJsSize = info.Size()
		}

		// Get Node.js PID if running
		nodePID := 0
		if nodeServerCmd != nil && nodeServerCmd.Process != nil {
			nodePID = nodeServerCmd.Process.Pid
		}

		// Read logs
		stdout, _ := os.ReadFile("/app/logs/nodejs-stdout.log")
		stderr, _ := os.ReadFile("/app/logs/nodejs-stderr.log")

		response := map[string]interface{}{
			"service":           "cambrian-mcp-server-tee-bootstrap-debug",
			"nodeServerRunning": nodeServerRunning,
			"nodePID":           nodePID,
			"appDirectory":      appContents,
			"distDirectory":     distContents,
			"distError":         distError,
			"indexJsExists":     indexJsExists,
			"indexJsSize":       indexJsSize,
			"secrets":           len(decryptedSecrets),
			"env": map[string]string{
				"TEE_MODE":         os.Getenv("TEE_MODE"),
				"CONTAINER_DIGEST": os.Getenv("CONTAINER_DIGEST"),
				"PORT":             os.Getenv("PORT"),
				"NODE_ENV":         os.Getenv("NODE_ENV"),
			},
			"stdout": string(stdout),
			"stderr": string(stderr),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Proxy MCP endpoints to Node.js
	router.HandleFunc("/mcp", proxyToNodeJS).Methods("GET", "POST", "OPTIONS")
	router.HandleFunc("/attestation", proxyToNodeJS).Methods("GET")
	router.HandleFunc("/sse", proxyToNodeJS).Methods("GET")
	router.HandleFunc("/messages", proxyToNodeJS).Methods("POST")

	// Server info (root) - proxy to Node.js if running, otherwise show bootstrap info
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if nodeServerRunning {
			proxyToNodeJS(w, r)
		} else {
			response := map[string]interface{}{
				"service":     "cambrian-mcp-server-tee-bootstrap",
				"version":     "1.0.0",
				"teeMode":     os.Getenv("TEE_MODE") == "true",
				"nodeServer":  nodeServerRunning,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}).Methods("GET")

	httpServer = &http.Server{
		Addr:         ":" + *port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logger.Printf("🌐 Health server listening on :%s", *port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Health server error: %v", err)
	}
}
