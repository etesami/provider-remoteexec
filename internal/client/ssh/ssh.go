package ssh

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/errors"
)

const (
	// default Secret field names for TLS certificates, like managed by cert-manager
	defaultClientCertificateKeyField  = "tls.key"
	defaultClientCertificateCertField = "tls.crt"

	errCannotParse                    = "cannot parse credentials"
	errMissingClientCertSecretRefKeys = "missing client cert ref secret name or namespace"
	errCannotReadClientCertSecret     = "cannot read client cert secret"
)

// NewSSHClient creates a new SSHClient with supplied credentials
func NewSSHClient(ctx context.Context, data []byte) (*ssh.Client, error) { // nolint: gocyclo
	logger := log.FromContext(ctx).WithName("[SSHClient]")
	logger.Info("SSHClient starting...")
	kc := Config{}

	logger.Info("Unmarshalling data...")
	logger.Info("Data", "data", string(data))
	if err := json.Unmarshal(data, &kc); err != nil {
		logger.Error(err, "Error unmarshalling data")
		return nil, errors.Wrap(err, errCannotParse)
	}
	logger.Info("Unmarshalled finished...")

	username := kc.Username
	remoteHost := kc.Host
	config := &ssh.ClientConfig{}
	config.User = username

	logger.Info("Data", "username", username, "remoteHost", remoteHost)

	if kc.PrivateKey != "" {

		privateKeyBytes, err := base64.StdEncoding.DecodeString(kc.PrivateKey)
		if err != nil {
			// log.Fatal("Error decoding base64 private key:", err)
			logger.Error(err, "Error decoding base64 private key")
		}

		signer, err := ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			// log.Fatalf("Failed to parse private key: %v", err)
			logger.Error(err, "Failed to parse private key")
		}

		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password("password"), // Replace with your remote server password
		}
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	client, err := ssh.Dial("tcp", remoteHost, config) // Replace with your remote server address and port
	if err != nil {
		// log.Fatalf("Failed to dial: %v", err)
		logger.Error(err, "Failed to dial")
	}

	return client, nil
}
