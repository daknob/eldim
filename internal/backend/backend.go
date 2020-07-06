package backend

import (
	"context"
	"io"
)

/*
Config is the interface that is required by
eldim backend configuration nodes
*/
type Config interface {
	Validate() error
	Name() string
}

/*
Client is the interface that is required by
eldim backend clients
*/
type Client interface {
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error

	BucketExists(ctx context.Context, name string) (bool, error)
	ObjectExists(ctx context.Context, name string) (bool, error)

	Name() string
	Bucket() string
	BackendName() string

	UploadFile(ctx context.Context, name string, file io.Reader, filesize int64) error
}
