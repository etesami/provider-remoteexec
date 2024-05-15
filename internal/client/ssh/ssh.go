package ssh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/errors"
)

const (
	// default Secret field names for TLS certificates, like managed by cert-manager
	// defaultClientCertificateKeyField  = "tls.key"
	// defaultClientCertificateCertField = "tls.crt"

	errCannotParse                    = "cannot parse credentials"
	errMissingClientCertSecretRefKeys = "missing client cert ref secret name or namespace"
	errCannotReadClientCertSecret     = "cannot read client cert secret"
)

// NewSSHClient creates a new SSHClient with supplied credentials
func NewSSHClientwithKey(ctx context.Context, data []byte) (*ssh.Client, error) { // nolint: gocyclo
	logger := log.FromContext(ctx).WithName("[SSHClient]")
	kc := Config{}

	if err := json.Unmarshal(data, &kc); err != nil {
		return nil, errors.Wrap(err, errCannotParse)
	}

	username := kc.Username
	remoteHost := kc.Host
	config := &ssh.ClientConfig{}
	config.User = username

	if kc.PrivateKey != "" {

		privateKeyBytes, err := base64.StdEncoding.DecodeString(kc.PrivateKey)
		if err != nil {
			logger.Error(err, "Error decoding base64 private key")
		}

		signer, err := ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
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
		logger.Error(err, "Failed to dial")
	}

	return client, nil
}

func NewSSHClientwithMap(ctx context.Context, data map[string][]byte) (*ssh.Client, error) { // nolint: gocyclo
	logger := log.FromContext(ctx).WithName("[SSHClient]")
	kc := Config{}

	// if err := json.Unmarshal(data, &kc); err != nil {
	// 	return nil, errors.Wrap(err, errCannotParse)
	// }

	// check if keys exist in the data and assign to the struct
	if _, ok := data["username"]; !ok {
		return nil, errors.New("username key not found in the data")
	}
	if _, ok := data["remote_host_ip"]; !ok {
		return nil, errors.New("remote_host_ip key not found in the data")
	}
	if _, ok := data["remote_host_port"]; !ok {
		return nil, errors.New("remote_host_port key not found in the data")
	}
	// should set at least private_key or password keys
	if _, ok := data["private_key"]; !ok {
		if _, ok := data["password"]; !ok {
			return nil, errors.New("private_key or password key not found in the data")
		}
		kc.Password = string(data["password"])
	} else {
		kc.PrivateKey = string(data["private_key"])
	}

	kc.Username = string(data["username"])
	kc.Host = string(data["remote_host_ip"]) + ":" + string(data["remote_host_port"])

	config := &ssh.ClientConfig{}
	config.User = kc.Username

	if kc.PrivateKey != "" {

		privateKeyBytes, err := base64.StdEncoding.DecodeString(kc.PrivateKey)
		if err != nil {
			logger.Error(err, "Error decoding base64 private key")
		}

		signer, err := ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			logger.Error(err, "Failed to parse private key")
		}

		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(kc.Password), // Replace with your remote server password
		}
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	client, err := ssh.Dial("tcp", kc.Host, config) // Replace with your remote server address and port
	if err != nil {
		logger.Error(err, "Failed to dial")
	}

	return client, nil
}

// RunScript function execute the given script over an ssh session
func RunScript(ctx context.Context, client *ssh.Client, script string, sudoEnabled bool) (string, error) {
	logger := log.FromContext(ctx).WithName("[RunScript]")

	// Need to create different session for each command
	// Create a temporary file on the remote host
	tmpFile, err := createTempFile(client)
	if err != nil {
		logger.Error(err, "Failed to create temporary file")
	}
	// remove trailing newline
	tmpFile = tmpFile[:len(tmpFile)-1]

	// Write the script content to the temporary file
	err = writeScriptToFile(client, tmpFile, script)
	if err != nil {
		logger.Error(err, "Failed to write script content")
	}

	// make the tmpFile executable
	cmdExec := "chmod +x " + tmpFile

	// Run the script on the remote host
	cmd := ""
	if sudoEnabled {
		cmd = "sudo "
	}
	cmd = cmdExec + " && " + cmd + tmpFile

	session, err := client.NewSession()
	if err != nil {
		logger.Error(err, "Failed to create session")
		return "", err
	}
	defer func() {
		if cerr := session.Close(); cerr != nil {
			logger.Error(err, "Error closing file:")
		}
	}()
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		logger.Error(err, "Failed to run script")
		return string(output), err
	}

	// Clean up the temporary file
	err = cleanUpTempFile(client, tmpFile)
	if err != nil {
		logger.Error(err, "Failed to clean up temporary file")
	}

	return string(output), nil
}

func createTempFile(client *ssh.Client) (string, error) {

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := session.Close(); cerr != nil {
			// Handle the error appropriately, e.g., log it or return it
			fmt.Println("Error closing session:", cerr)
		}
	}()

	tmpFile, err := session.CombinedOutput("mktemp")
	if err != nil {
		return "", err
	}
	return string(tmpFile), nil
}

func writeScriptToFile(client *ssh.Client, tmpFile, scriptContent string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() {
		if cerr := session.Close(); cerr != nil {
			// Handle the error appropriately, e.g., log it or return it
			fmt.Println("Error closing session:", cerr)
		}
	}()

	cmd := "cat > " + tmpFile + " << EOF\n" + scriptContent + "\nEOF"
	return session.Run(cmd)
}

func cleanUpTempFile(client *ssh.Client, tmpFile string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() {
		if cerr := session.Close(); cerr != nil {
			// Handle the error appropriately, e.g., log it or return it
			fmt.Println("Error closing session:", cerr)
		}
	}()

	cmd := "rm -f " + tmpFile
	return session.Run(cmd)
}
