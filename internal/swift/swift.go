package swift

import (
	"fmt"

	"github.com/ncw/swift"
)

/*
BackendConfig is the data structure containing all information
required to connect to a single OpenStack Swift server
*/
type BackendConfig struct {
	BackendName   string `yaml:"name"`
	Username      string `yaml:"username"`
	APIKey        string `yaml:"apikey"`
	AuthURL       string `yaml:"authurl"`
	Region        string `yaml:"region"`
	Container     string `yaml:"container"`
	ExpireSeconds int    `yaml:"expireseconds"`
}

/*
Validate validates the Openstack Swift Backend and returns the
first error that occured during validation.
*/
func (conf *BackendConfig) Validate() error {
	/* Check if backend has a name */
	if conf.BackendName == "" {
		return fmt.Errorf("OpenStack Swift Backend requires a name")
	}

	/* Check if all details are supplied */
	if conf.Username == "" || conf.APIKey == "" ||
		conf.AuthURL == "" || conf.Region == "" ||
		conf.Container == "" {
		return fmt.Errorf("All fields are required for OpenStack Swift backends to work")
	}

	/* Ensure expire seconds is not negative */
	if conf.ExpireSeconds < 0 {
		return fmt.Errorf("Expiry Seconds cannot be a negative number")
	}

	/* Attempt to connect to OpenStack Swift Backend */
	osConn := swift.Connection{
		UserName:     conf.Username,
		ApiKey:       conf.APIKey,
		AuthUrl:      conf.AuthURL,
		Domain:       "default",
		Region:       conf.Region,
		AuthVersion:  3,
		EndpointType: swift.EndpointTypePublic,
		UserAgent:    "eldim",
	}

	err := osConn.Authenticate()
	if err != nil {
		return fmt.Errorf("Failed to authenticate to Backend: %v", err)
	}

	/* Check if container (bucket) exists */
	_, _, err = osConn.Container(conf.Container)
	if err != nil {
		return fmt.Errorf("OpenStack Swift Backend Container Error: %v", err)
	}

	/* Disconnect from OpenStack */
	osConn.UnAuthenticate()

	return nil
}

/*
Name returns the name configured for this OpenStack Swift Backend
*/
func (conf *BackendConfig) Name() string {
	if conf.BackendName == "" {
		conf.BackendName = "Unnamed Openstack Swift Backend"
	}
	return conf.BackendName
}
