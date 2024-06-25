package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/crossplane/provider-remoteexec/apis/ssh/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/pkg/sftp"
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
		logger.Error(err, "Failed to dial: "+string(kc.Host)+" with username "+kc.Username+" error: "+err.Error())
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
	if ok := isValidIPv4(string(data["remote_host_ip"])); !ok {
		return nil, errors.New("Remote host address is not a valid: " + string(data["remote_host_ip"]))
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

		// privateKeyBytes, err := base64.StdEncoding.DecodeString(kc.PrivateKey)
		// if err != nil {
		// 	logger.Error(err, "Error decoding base64 private key")
		// }

		privateKeyBytes := []byte(kc.PrivateKey)
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

	logger.Info("Connecting to remote host: " + kc.Host + " with username: " + kc.Username)
	client, err := ssh.Dial("tcp", kc.Host, config) // Replace with your remote server address and port
	if err != nil {
		return nil, errors.New("Failed to dial: " + string(kc.Host) + " with username " + kc.Username + " error: " + err.Error())
	}

	return client, nil
}

func isValidIPv4(inputAddress string) bool {
	// Check if the input is a valid IPv4 address
	// Check if the input is a valid IPv4 address
	ipv4Pattern := `^(\d{1,3}\.){3}\d{1,3}$`
	ipv4Regex := regexp.MustCompile(ipv4Pattern)

	// Regular expression pattern to match URL with anything[dot]anything
	urlPattern := `^[^\.]+(\.[^\.]+)+$`
	urlRegex := regexp.MustCompile(urlPattern)

	// Check if the input string matches IPv4 pattern or URL pattern
	if ipv4Regex.MatchString(inputAddress) || urlRegex.MatchString(inputAddress) {
		return true
	}
	return false
}

// send a file to the remote host
func sendFile(client *ssh.Client, fileContent, remotePath string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer closeSession(session)

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer func() {
		err := session.Close()
		if err != nil {
			_ = fmt.Errorf("failed to close sftp session: %w", err)
		}
	}()

	// Convert the string content to a byte buffer
	fileBuffer := bytes.NewBufferString(fileContent)

	// Open the destination file on the remote host
	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		_ = fmt.Errorf("Failed to create remote file: %s", err)
	}
	defer func() {
		err := remoteFile.Close()
		if err != nil {
			_ = fmt.Errorf("failed to close remote file: %w", err)
		}
	}()

	// Write the file content to the remote file
	_, err = fileBuffer.WriteTo(remoteFile)
	if err != nil {
		_ = fmt.Errorf("Failed to write to remote file: %s", err)
	}

	return nil
}

// ReplaceVars replaces the variables in the script with the given values
func ReplaceVars(script string, vars []v1alpha1.Var) string {
	// variables are in the format of {{VAR_NAME}}
	// we remove the {{ and }} and replace the VAR_NAME with the value
	for _, v := range vars {
		script = strings.ReplaceAll(script, "{{"+v.Name+"}}", v.Value)
	}
	return script
}

// RunScript function execute the given script over an ssh session
func RunScript(ctx context.Context, client *ssh.Client, script string, vars []v1alpha1.Var, sudoEnabled bool) (string, error) {
	logger := log.FromContext(ctx).WithName("[RunScript]")

	// Need to create different session for each command
	// Create a temporary file on the remote host
	// tmpFile, err := createTempFile(client)
	// if err != nil {
	// 	logger.Error(err, "Failed to create temporary file")
	// }
	// // remove trailing newline
	// tmpFile = tmpFile[:len(tmpFile)-1]

	// replace the variables in the script
	script = ReplaceVars(script, vars)

	// Write the script content to the temporary file
	// err = writeScriptToFile(client, tmpFile, script)
	// if err != nil {
	// 	logger.Error(err, "Failed to write script content")
	// }

	// send the script to the remote host
	remoteFile := "/tmp/" + randomFileName(8)
	err := sendFile(client, script, remoteFile)
	if err != nil {
		logger.Error(err, "Failed to send script content")
	}

	// make the tmpFile executable
	cmdExec := "chmod +x " + remoteFile

	// Run the script on the remote host
	cmd := ""
	if sudoEnabled {
		cmd = "sudo "
	}
	cmd = cmdExec + " && " + cmd + remoteFile

	session, err := client.NewSession()
	if err != nil {
		logger.Error(err, "Failed to create session")
		return "", err
	}
	defer closeSession(session)

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return string(output), err
	}

	logger.Info("Script executed, output: " + string(output))

	// Clean up the temporary file
	err = cleanUpTempFile(client, remoteFile)
	if err != nil {
		logger.Error(err, "Failed to clean up temporary file")
	}

	return string(output), nil
}

func closeSession(session *ssh.Session) {
	err := session.Close()
	if err != nil {
		_ = fmt.Errorf("failed to close session: %w", err)
	}
}

func createTempFile(client *ssh.Client) (string, error) {

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer closeSession(session)

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
	defer closeSession(session)

	cmd := "cat > " + tmpFile + " << EOF\n" + scriptContent + "\nEOF"
	return session.Run(cmd)
}

func cleanUpTempFile(client *ssh.Client, tmpFile string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer closeSession(session)

	cmd := "rm -f " + tmpFile
	return session.Run(cmd)
}

func randomFileName(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return "tmp." + hex.EncodeToString(bytes)
}
