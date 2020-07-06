package s3

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go"
)

/*
BackendConfig is the data structure containing all information
required to connect to an S3 backend
*/
type BackendConfig struct {
	BackendName string `yaml:"name"`
	Endpoint    string `yaml:"endpoint"`
	Bucket      string `yaml:"bucketname"`
	Region      string `yaml:"region"`
	AccessKey   string `yaml:"accesskey"`
	SecretKey   string `yaml:"secretkey"`
}

/*
Validate validates the S3 Storage Backend and returns the
first error that occured during validation.
*/
func (conf *BackendConfig) Validate() error {
	/* Check if backend has a name */
	if conf.BackendName == "" {
		return fmt.Errorf("S3 Backend requires a name")
	}

	/* Check if all details are supplied */
	if conf.Endpoint == "" || conf.Bucket == "" || conf.AccessKey == "" || conf.SecretKey == "" || conf.Region == "" {
		return fmt.Errorf("All fields are required for S3 backends to work")
	}

	/* Attempt to connect to the Backend */
	mc, err := minio.NewWithRegion(conf.Endpoint, conf.AccessKey, conf.SecretKey, true, conf.Region)
	if err != nil {
		return fmt.Errorf("Failed to connect to Backend: %v", err)
	}

	/* Set appropriate app information */
	mc.SetAppInfo("eldim", "")

	/* Check if bucket exists */
	exists, err := mc.BucketExists(conf.Bucket)
	if err != nil {
		return fmt.Errorf("Failed to check if bucket exists: %v", err)
	}
	if !exists {
		return fmt.Errorf("Bucket does not exist: %s", conf.Bucket)
	}

	return nil
}

/*
Name returns the name configured for this S3 Backend
*/
func (conf *BackendConfig) Name() string {
	if conf.BackendName == "" {
		conf.BackendName = "Unnamed S3 Backend"
	}
	return conf.BackendName
}

/*
Client is an S3 Backend Client Object
*/
type Client struct {
	Conn   *minio.Client
	Config BackendConfig
}

/*
New creates a new S3 Backend client
*/
func New(ctx context.Context, conf BackendConfig) *Client {
	var ret Client
	ret.Config = conf
	ret.Conn = nil

	return &ret
}

/*
Connect connects the S3 Backend client to
the backend service and authenticates
*/
func (c *Client) Connect(ctx context.Context) error {
	/* Create new S3 Client */
	mc, err := minio.NewWithRegion(c.Config.Endpoint, c.Config.AccessKey,
		c.Config.SecretKey, true, c.Config.Region)
	if err != nil {
		return fmt.Errorf("Failed to connect to S3: %v", err)
	}

	/* Set App Info */
	mc.SetAppInfo("eldim", "")

	c.Conn = mc
	return nil
}

/*
Disconnect terminates the connection of the
S3 client with the backend server
*/
func (c *Client) Disconnect(ctx context.Context) error {
	return nil
}

/*
BucketExists returns if a particular bucket exists and is
reachable by the S3 client
*/
func (c *Client) BucketExists(ctx context.Context, name string) (bool, error) {
	return c.Conn.BucketExists(name)
}

/*
ObjectExists returns if a particular object exists and is
reachable by the S3 client
*/
func (c *Client) ObjectExists(ctx context.Context, name string) (bool, error) {

	_, err := c.Conn.StatObject(c.Config.Bucket, name, minio.StatObjectOptions{})
	if err != nil {
		switch minio.ToErrorResponse(err).Code {
		case "NoSuchKey":
			return false, nil
		default:
			return false, fmt.Errorf("Failed checking if object exists: %v", err)
		}
	}

	return true, nil
}

/*
Name returns the S3 Client Name
*/
func (c *Client) Name() string {
	return c.Config.Name()
}

/*
Bucket returns the S3 Bucket Name
*/
func (c *Client) Bucket() string {
	return c.Config.Bucket
}

/*
BackendName returns 'S3'
*/
func (c *Client) BackendName() string {
	return "S3"
}

/*
UploadFile uploads a file to the
S3 Backend, with a name of name.
*/
func (c *Client) UploadFile(ctx context.Context, name string, file io.Reader, filesize int64) error {

	wr, err := c.Conn.PutObjectWithContext(ctx, c.Config.Bucket, name, file, filesize, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("Failed to upload file: %v", err)
	}
	if filesize != wr {
		return fmt.Errorf("Bytes uploaded is not the same as file size: %d vs %d", wr, filesize)
	}

	return nil
}
