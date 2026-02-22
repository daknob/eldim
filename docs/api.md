# API Documentation

eldim exposes an HTTP API for all servers to upload data. Here you can find
all the currently supported calls to this API:

## GET /

By sending a `GET` request to `/`, eldim will either print some information
about it, or nothing, depending on the value of `servertokens` in the
configuration file.

## POST /api/v1/file/upload/

By sending a `POST` request to `/api/v1/file/upload/`, you can upload files
to eldim. Currently there are two parameters that are required:

### filename

This is of type `string`, and must contain the desired name of the file.
Spaces or symbols that are not normal for files are not recommended, since
they may not be supported by the backends. Filenames containing null bytes,
path traversal components (`.` or `..`), or empty path segments (such as
leading, trailing, or consecutive slashes) will be rejected with `HTTP 400`.

### file

This `POST` parameter is the actual file. Send the entire file here that has
to be uploaded here.

This API call will return `HTTP 200` and print `Ok` if the upload succeeded.
It will return `HTTP 409` if the same file is already being uploaded by another
request to the same eldim instance. Any other HTTP Status Code or message is
an error.

> [!NOTE]
> As the requested `filename` may only exist (for whatever reason) only in some
> backends / buckets and not all of them, the `HTTP 409` error is likely not
> retriable and a new `filename` will probably have to be set.

### password

This `POST` parameter is a string that specifies a password, which will be
checked against `eldim`'s `clients.yml` and will identify hosts based on their
password key, instead of their IP Address. Password checks take precedence over
IP Address checks. The password must be between 32 and 128 characters for
security reasons.
