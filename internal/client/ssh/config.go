package ssh

// Config is a SSH client configuration
type Config struct {
	Host       string `json:"remote_host"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}
