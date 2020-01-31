package main

/*
config is the data structure outlying the configuration file of eldim
*/
type config struct {
	/* Web Server Settings */
	ListenPort   int   `yaml:"listenport"`
	ServerTokens bool  `yaml:"servertokens"`
	MaxUploadRAM int64 `yaml:"maxuploadram"`

	/* TLS Settings */
	TLSChainPath string `yaml:"tlschain"`
	TLSKeyPath   string `yaml:"tlskey"`

	/* Backend Server */
	SwiftBackends []openStackSettings `yaml:"swiftbackends"`

	/* Clients */
	ClientFile string `yaml:"clientfile"`

	/* System */
	TempUploadPath string `yaml:"tempuploadpath"`

	/* Encryption */
	EncryptionKey string `yaml:"encryptionkey"`

	/* Prometheus Metrics */
	PrometheusEnabled  bool   `yaml:"prometheusenabled"`
	PrometheusAuthUser string `yaml:"prometheusauthuser"`
	PrometheusAuthPass string `yaml:"prometheusauthpass"`
}

/*
openStackSettings is the data structure containing all information
required to connect to a single OpenStack Swift server
*/
type openStackSettings struct {
	Name          string `yaml:"name"`
	Username      string `yaml:"username"`
	Apikey        string `yaml:"apikey"`
	AuthURL       string `yaml:"authurl"`
	Region        string `yaml:"region"`
	Container     string `yaml:"container"`
	ExpireSeconds int    `yaml:"expireseconds"`
}

/*
clientInfo is the data structure containing all information about
a client that can connect to the eldim service
*/
type clientInfo struct {
	Name     string   `yaml:"name"`
	Ipv4     []string `yaml:"ipv4"`
	Ipv6     []string `yaml:"ipv6"`
	Password string   `yaml:"password"`
}
