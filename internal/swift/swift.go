package swift

import (
	"context"
	"fmt"
	"io"

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
Validate validates the OpenStack Swift Backend and returns the
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
		return fmt.Errorf("all fields are required for OpenStack Swift backends to work")
	}

	/* Ensure expire seconds is not negative */
	if conf.ExpireSeconds < 0 {
		return fmt.Errorf("expiry Seconds cannot be a negative number")
	}

	/* Attempt to connect to OpenStack Swift Backend */
	client := New(context.Background(), *conf)

	err := client.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("failed to authenticate to Backend: %v", err)
	}

	/* Check if container (bucket) exists */
	exists, err := client.BucketExists(context.Background(), conf.Container)
	if err != nil {
		return fmt.Errorf("OpenStack Swift Backend Container Error: %v", err)
	}
	if !exists {
		return fmt.Errorf("OpenStack Swift Container does not exist: %s", conf.Container)
	}

	/* Disconnect from OpenStack */
	client.Disconnect(context.Background())

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

/*
Client is an OpenStack Swift Client Object
*/
type Client struct {
	Conn   swift.Connection
	Config BackendConfig
}

/*
New creates a new OpenStack Swift client
*/
func New(ctx context.Context, conf BackendConfig) *Client {
	var ret Client
	ret.Config = conf
	ret.Conn = swift.Connection{
		UserName:     conf.Username,
		ApiKey:       conf.APIKey,
		AuthUrl:      conf.AuthURL,
		Domain:       "default",
		Region:       conf.Region,
		AuthVersion:  3,
		EndpointType: swift.EndpointTypePublic,
		UserAgent:    "eldim",
	}
	return &ret
}

/*
Connect connects the OpenStack Swift client to the backend
service and authenticates
*/
func (c *Client) Connect(ctx context.Context) error {
	return c.Conn.Authenticate()
}

/*
Disconnect terminates the connection of the OpenStack Swift
client with the backend server
*/
func (c *Client) Disconnect(ctx context.Context) error {
	c.Conn.UnAuthenticate()
	return nil
}

/*
BucketExists returns if a particular bucket exists and is
reachable by the OpenStack Swift client
*/
func (c *Client) BucketExists(ctx context.Context, name string) (bool, error) {
	_, _, err := c.Conn.Container(name)
	if err == swift.ContainerNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check if bucket exists: %v", err)
	}

	return true, nil
}

/*
ObjectExists returns if a particular object exists and is
reachable by the OpenStack Swift client
*/
func (c *Client) ObjectExists(ctx context.Context, name string) (bool, error) {
	_, _, err := c.Conn.Object(c.Bucket(), name)
	if err == swift.ObjectNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check if object exists: %v", err)
	}

	return true, nil
}

/*
Name returns the OpenStack Swift Client Name
*/
func (c *Client) Name() string {
	return c.Config.Name()
}

/*
Bucket returns the OpenStack Swift Container Name
*/
func (c *Client) Bucket() string {
	return c.Config.Container
}

/*
BackendName returns 'OpenStack Swift'
*/
func (c *Client) BackendName() string {
	return "OpenStack Swift"
}

/*
UploadFile uploads a file to the OpenStack Swift Backend, with
a name of name.
*/
func (c *Client) UploadFile(ctx context.Context, name string, file io.Reader, filesize int64) error {

	_, err := c.Conn.ObjectPut(c.Bucket(), name, file, false, "",
		"application/vnd.age", map[string]string{
			"X-Delete-After": fmt.Sprintf("%d", c.Config.ExpireSeconds),
		})
	if err != nil {
		return fmt.Errorf("failed to upload file: %v", err)
	}

	return nil
}
