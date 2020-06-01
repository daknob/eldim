package gcs

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

/*
BackendConfig is the data structure containing all information
required to connect to a Google Cloud Storage account
*/
type BackendConfig struct {
	BackendName     string `yaml:"name"`
	CredentialsFile string `yaml:"credsfile"`
	Bucket          string `yaml:"bucketname"`
}

/*
Validate validates the Google Cloud Storage Backend and
returns the first error that occured during validation.
*/
func (conf *BackendConfig) Validate() error {
	/* Check if backend has a name */
	if conf.BackendName == "" {
		return fmt.Errorf("Google Cloud Storage Backend requires a name")
	}

	/* Check if all details are supplied */
	if conf.CredentialsFile == "" || conf.Bucket == "" {
		return fmt.Errorf("All fields are required for Google Cloud Storage backends to work")
	}

	/* Attempt to connect to the Backend */
	client := New(context.Background(), *conf)

	err := client.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("Failed to authenticate to Backend: %v", err)
	}

	/* Check if the bucket exists */
	exists, err := client.BucketExists(context.Background(), conf.Bucket)
	if err != nil {
		return fmt.Errorf("Google Cloud Storage Backend Bucket Error: %v", err)
	}
	if !exists {
		return fmt.Errorf("Google Cloud Storage Container does not exist: %s", conf.Bucket)
	}

	/* Disconnect from OpenStack */
	client.Disconnect(context.Background())

	return nil
}

/*
Name returns the name configured for this Google Cloud Storage Backend
*/
func (conf *BackendConfig) Name() string {
	if conf.BackendName == "" {
		conf.BackendName = "Unnamed Google Cloud Storage Backend"
	}
	return conf.BackendName
}

/*
Client is an Google Cloud Storage Client Object
*/
type Client struct {
	Conn   *storage.Client
	Config BackendConfig
}

/*
New creates a new Google Cloud Storage client
*/
func New(ctx context.Context, conf BackendConfig) *Client {
	var ret Client
	ret.Config = conf
	ret.Conn = nil

	return &ret
}

/*
Connect connects the Google Cloud Storage client to
the backend service and authenticates
*/
func (c *Client) Connect(ctx context.Context) error {
	gcl, err := storage.NewClient(ctx,
		option.WithCredentialsFile(c.Config.CredentialsFile))
	if err != nil {
		return fmt.Errorf("Failed to connect to GCS: %v", err)
	}
	c.Conn = gcl
	return nil
}

/*
Disconnect terminates the connection of the Google
Cloud Storage client with the backend server
*/
func (c *Client) Disconnect(ctx context.Context) error {
	return c.Conn.Close()
}

/*
BucketExists returns if a particular bucket exists and is
reachable by the Google Cloud Storage client
*/
func (c *Client) BucketExists(ctx context.Context, name string) (bool, error) {
	_, err := c.Conn.Bucket(name).Attrs(ctx)
	if err == storage.ErrBucketNotExist {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("Failed to check if bucket exists: %v", err)
	}

	return true, nil
}

/*
ObjectExists returns if a particular object exists and is
reachable by the Google Cloud Storage client
*/
func (c *Client) ObjectExists(ctx context.Context, name string) (bool, error) {
	_, err := c.Conn.Bucket(c.Bucket()).Object(name).Attrs(ctx)
	if err == storage.ErrObjectNotExist {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("Failed to check if object exists: %v", err)
	}

	return true, nil
}

/*
Name returns the Google Cloud Storage Client Name
*/
func (c *Client) Name() string {
	return c.Config.Name()
}

/*
Bucket returns the Google Cloud Storage Bucket Name
*/
func (c *Client) Bucket() string {
	return c.Config.Bucket
}

/*
BackendName returns 'Google Cloud Storage'
*/
func (c *Client) BackendName() string {
	return "Google Cloud Storage"
}

/*
UploadFile uploads a file to the Google Cloud Storage
Backend, with a name of name.
*/
func (c *Client) UploadFile(ctx context.Context, name string, file *[]byte) error {

	w := c.Conn.Bucket(c.Bucket()).Object(name).NewWriter(ctx)
	w.ObjectAttrs.ContentType = "application/octet-stream"
	_, err := w.Write(*file)
	if err != nil {
		return fmt.Errorf("Failed to write to object: %v", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("Failed to upload file: %v", err)
	}

	return nil
}
