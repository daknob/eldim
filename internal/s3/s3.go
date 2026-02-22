package s3

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"log/slog"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

/*
conditionalWriteSupport tracks S3 endpoints that support the
If-None-Match header. Endpoints are assumed to support it until
a 501 response proves otherwise (e.g. Backblaze B2).
*/
var conditionalWriteSupport sync.Map

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
	SendMD5     bool   `yaml:"sendcontentmd5"`
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
		return fmt.Errorf("all fields are required for S3 backends to work")
	}

	/* Attempt to connect to the Backend */
	mc, err := minio.New(conf.Endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(
			conf.AccessKey,
			conf.SecretKey, ""),
		Secure: true,
		Region: conf.Region,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to Backend: %v", err)
	}

	/* Set appropriate app information */
	mc.SetAppInfo("eldim", "")

	/* Check if bucket exists */
	exists, err := mc.BucketExists(context.Background(), conf.Bucket)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %v", err)
	}
	if !exists {
		return fmt.Errorf("bucket does not exist: %s", conf.Bucket)
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
	mc, err := minio.New(c.Config.Endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(
			c.Config.AccessKey,
			c.Config.SecretKey, ""),
		Secure: true,
		Region: c.Config.Region,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to S3: %v", err)
	}

	/* Set App Info */
	mc.SetAppInfo("eldim", "")

	c.Conn = mc

	/* Assume the endpoint supports conditional writes until proven otherwise */
	conditionalWriteSupport.LoadOrStore(c.Config.Endpoint, true)

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
	return c.Conn.BucketExists(ctx, name)
}

/*
ObjectExists returns if a particular object exists and is
reachable by the S3 client
*/
func (c *Client) ObjectExists(ctx context.Context, name string) (bool, error) {

	_, err := c.Conn.StatObject(ctx, c.Config.Bucket, name, minio.StatObjectOptions{})
	if err != nil {
		switch minio.ToErrorResponse(err).Code {
		case "NoSuchKey":
			return false, nil
		default:
			return false, fmt.Errorf("failed checking if object exists: %v", err)
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
UploadFile uploads a file to the S3 Backend, with a name of name.
It uses If-None-Match to prevent overwriting existing files when the
endpoint supports it. Endpoints that return 501 (e.g. Backblaze B2)
are remembered and subsequent uploads skip the header.
*/
func (c *Client) UploadFile(ctx context.Context, name string, file io.Reader, filesize int64) error {

	opts := minio.PutObjectOptions{
		ContentType:    "application/vnd.age",
		SendContentMd5: c.Config.SendMD5,
	}

	/* Use If-None-Match unless the endpoint is known to not support it */
	val, _ := conditionalWriteSupport.Load(c.Config.Endpoint)
	supported, _ := val.(bool)
	if supported {
		opts.SetMatchETagExcept("*")
	}

	uinfo, err := c.Conn.PutObject(ctx, c.Config.Bucket, name, file, filesize, opts)
	if err != nil {
		/* If the endpoint does not support If-None-Match, remember and retry */
		if supported && minio.ToErrorResponse(err).StatusCode == http.StatusNotImplemented {
			conditionalWriteSupport.Store(c.Config.Endpoint, false)
			slog.Warn("S3 endpoint does not support If-None-Match, retrying without it", "endpoint", c.Config.Endpoint)

			if seeker, ok := file.(io.Seeker); ok {
				if _, seekErr := seeker.Seek(0, io.SeekStart); seekErr == nil {
					retryOpts := minio.PutObjectOptions{
						ContentType:    "application/vnd.age",
						SendContentMd5: c.Config.SendMD5,
					}
					uinfo, err = c.Conn.PutObject(ctx, c.Config.Bucket, name, file, filesize, retryOpts)
					if err != nil {
						/* If we still get 501 without the header, it was unrelated */
						if minio.ToErrorResponse(err).StatusCode == http.StatusNotImplemented {
							conditionalWriteSupport.Store(c.Config.Endpoint, true)
						}
						return fmt.Errorf("failed to upload file: %v", err)
					}
					if filesize != uinfo.Size {
						return fmt.Errorf("bytes uploaded is not the same as file size: %d vs %d", uinfo.Size, filesize)
					}
					return nil
				}
			}
			return fmt.Errorf("failed to upload file (endpoint does not support If-None-Match and retry not possible): %v", err)
		}

		return fmt.Errorf("failed to upload file: %v", err)
	}
	if filesize != uinfo.Size {
		return fmt.Errorf("bytes uploaded is not the same as file size: %d vs %d", uinfo.Size, filesize)
	}

	return nil
}
