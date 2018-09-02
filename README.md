# eldim
An OpenStack Swift File Upload Proxy

## Description
eldim is a web server that accepts file uploads from a particular set of
hosts, and its job is to encrypt them, and then store them in an OpenStack
Swift backend system.

It has a preconfigured ACL that only allows specific IP Addresses to access
the file upload service. After a file is uploaded, it is encrypted with a
symmetric key, and then uploaded to a configured Swift provider.

It has been designed to work as a standalone application, which means it must
not sit behind a proxy, but instead be exposed directly to the Internet.

## Design Decisions
The design of eldim is data agnostic, and tries to push the relevant logic
of all operations to the proper server. For example, the service itself does
not care what types of files are uploaded, or when they're uploaded, or what
they are. It simply receives a file, a file name, and then encrypts and
uploads this file under a specific name to the Object Storage.

In eldim's configuration file you can add a list of hosts, as well as their
(host)names, and eldim makes sure that all files uploaded from a particular
host will always have that host's name in their name. For example, files from
the host `mail.example.com`, will always have a file name starting with
`mail.example.com/`.

The data collection part is left to the servers sending data to it. It is
them who decide what to send, when to send it, and what operations, such as
compression for example, must be applied to the file.

## Security
In order for every server to be able to upload logs or backups to a central
object storage bucket, they need to have some secrets stored in them. For
example, in Swift, each server needs to have a username and an API key. This
is something that is not really secure, as compromising any server would give
full access to the backup repository. An attacker could download files, delete
files, change them, etc.

In eldim, the servers do not have any stored information, and instead just
upload the files to a single server. This server is the one with the access,
and can control what operations are being performed, and by whom.

The way eldim works, no server is allowed to mess with another server's files.
Server `mail.example.com` cannot upload files as `ftp.example.com`, even if
they upload to the very same bucket. eldim automatically prepends all file
uploads with the server hostname, which is inside its configuration file, and
not sent by the servers themselves.

Moreover, eldim will reject files that already exist. If the file
`mail.example.com/2018-01-01/mail.log.tgz` already exists in the object store,
it will not allow for it to be overwritten. This check is in place to prevent
a hacked server from overwritting all previous log entries with empty data,
effectively deleting everything.

Finally, eldim works only over HTTPS. This decision is hard coded inside the
server itself, and cannot be changed by the configuration file. A code change
is required. It is configured to only work with TLSv1.2, the only currently
secure version of TLS, but currently it may accept some more weak ciphers
and not only the most secure ones.

### Encryption
For file encryption and decryption eldim uses a fairly known algorithm, called
[TripleSec](https://keybase.io/triplesec/). It is essentially three
cryptographic algorithms combined into a single library. It uses AES, Salsa20,
and Twofish.

It is entirely overkill for the purposes of this tool, but it is a simple and
nice library that exposes a single function for encryption, and everything is
handled automatically. There's no need to do HMACs, hashes, padding, IVs, or
anything, and works quite well. It also comes with its own storage format,
so the only output is a byte array that's just written to a file. However,
TripleSec is the reason uploads may need up to `2*sizeof(file)` in terms of
RAM.

## How to run eldim
eldim runs as a daemon, since it has to listen for HTTPS requests
continuously. For this reason, you need to ensure that the binary is
running all the time. The recommended way of achieving this is through your
operating system's startup / init system. If you are using `systemd`, a basic
unit file is provided in this repository for you to use.

As with any software, it is **not** recommended to run eldim as `root`. For
this reason, you should create an `eldim` user. The included `systemd` unit
file assumes the `eldim` user exists in the system.

You can create such user by running:

```bash
sudo adduser -s /usr/sbin/nologin -r -M eldim
```

When executed, eldim has two command line flags that you can use to configure
it before it even reads the configuration file. They are:

* `-j`: When set, it will output all logs in JSON format, instead of plaintext
* `-c`: The path to the configuration file

## Metrics
As of `eldim v0.2.0`, eldim supports metrics exporting using Prometheus. In
order to access the metrics, Prometheus has to be enabled from the
configuration file. eldim **requires** HTTP Basic Authentication on the
Metrics URL, and it is only available over HTTPS, through the same TCP port as
the public API. For security reasons, both the username and password must be
20-128 characters long.

Currently the following metrics are exposed by `eldim`:

### HTTP Requests Served
eldim exports `eldim_http_requests_served`, which is a counter vector, with
the following labels:

#### method
The `method` label contains the HTTP method that was used for this particular
HTTP request, and common values can be `GET` and `POST`.

#### path
The `path` label contains the URL of this HTTP Request, such as `/` or even
`/api/v1/file/upload/`.

#### status
The `status` label contains the HTTP Request Status Code that was returned,
i.e. `200` or `400`.

### Default Prometheus for Go Metrics
The Prometheus Client Library for Go exports a heap of metrics by default,
which include, among others, Go Garbage Collection metrics, Goroutine Info,
Go compiler version, Application Memory Info, Running Threads, as well as
Exporter Info, such as how many times the application data has been scraped
by Prometheus.

## Configuration
This section covers all the configuration options for eldim. There is a main
configuration file which can control the behavior and settings of the server,
as well as a secondary one that contains all the hosts who are authorized to
upload data.

### eldim.yml
This is the primary configuration file. It is recommended to store this in
`/etc/eldim/eldim.yml`, have it owned by `eldim:eldim`, and with permissions
`0400`.

Here you can find all the options of this file:

#### listenport
The `listenport` parameter accepts an integer number. This is the port number
the server will listen on for TLS connections.

#### servertokens
The `servertokens` parameter is a boolean and if set to `true`, eldim will not
try to hide that it is running in the system. For example, it will send the
`Server` HTTP header in its responses, and will print its version on `GET /`.

If it is set to `false`, it will not send the `Server` header, nor will it
print anything in its home page. However, if someone wants to figure out if
this server is running eldim, it is still trivial to do so.

#### maxuploadram
The `maxuploadram` parameter controls how many MBs of RAM should eldim 
allocate to new file uploads, before it starts saving the file to the disk
directly. If a file is uploaded and is above this number, processing it may
be slower. It is recommended to set this to about the largest file you can
expect, plus some more, but not to something over 10% of the total server
RAM.

#### tlschain
The `tlschain` parameter is the path to the TLS certificate chain file. If
you are using Let's Encrypt, this is the `fullchain.pem` file. Make sure
that this file also contains any intermediate certificates, and not only
your certificate, as some clients may not like this.

#### tlskey
The `tlskey` parameter is the path to the TLS certificate private key. If
you are using Let's Encrypt, this is the `privkey.pem` file.

#### clientfile
The `clientfile` parameter contains the path to the configuration file that
includes all clients who are authorized to upload data to eldim. More on
that file below.

#### tempuploadpath
The `tempuploadpath` parameter contains the path the server will upload
files to, for a brief period of time, before they are encrypted and then
uploaded. Depending on the file size, most uploads will not be here for more
than a few seconds, however in cases of unexpected server termination, some
unencrypted data may remain here.

#### encryptionkey
The `encryptionkey` is a string that will be used to generate the encrypted
files' symmetric key. Anyone who has access to this key can decrypt all files
that have been encrypted by eldim. Try to keep this a secret, and do not
transmit it insecurely.

#### swiftbackends
The `swiftbackends` is an array, which contains a list of all backends that
eldim will upload data to. More than one data storage is supported, but if you
add too many it may take excessive amounts of bandwidth and time to complete
the operations.

The fields of each array element are below:

##### name
The `name` parameter is a friendly name that you set to identify this backend
in eldim's logs, as well as its configuration file. It can be any string.

##### username
The `username` parameter is the OpenStack Swift v3 Username to authenticate to
the backend.

##### apikey
The `apikey` parameter is the OpenStack Swift v3 API Key (or, in some clouds,
password), to authenticate to the backend.

##### authurl
The `authurl` parameter is the OpenStack Swift v3 URL that eldim needs to
communicate with to connect and upload data. It must include the scheme
(`https://`).

##### region
The `region` parameter is the OpenStack Swift v3 Region. In some clouds this
value is case sensitive, so try both `xxx1` and `XXX1` if it doesn't work.

##### container
The `container` parameter is the OpenStack Swift v3 container, or bucket, in
which the data will be uploaded. This container must already exist before
any data is uploaded to it.

##### expireseconds
The `expireseconds` parameter is a special header sent with the file upload.
It is not supported by all clouds, but in the ones that do support it, eldim
will ask for this file to be deleted after so many seconds.

If you'd like to only keep your files for 90 days for example, and then have
them deleted, you can set this to `7776000`.

Since many providers offer a hot and a cold storage, you may want to add the
same provider two times, one with a hot storage container, and an expiry of
a week for example, or a month, and one with a cold storage container, and an
expiry of months or years. That way you can keep the most recent files
immediately available, while older files will take more time to be retrieved.

### clients.yml
This configuration file contains all the hosts that are authorized to upload
data to eldim. It is recommended to store this in `/etc/eldim/clients.yml`,
have it owned by `eldim:eldim`, and with permissions `0400`.

This file contains a YAML array, where each element contains the following
fields:

#### name
The `name` parameter contains this host's name. This will be prepended to
all file uploads from this host. If you set this to `example.com`, all files
uploaded by this host will start with `example.com/`.

#### ipv4
The `ipv4` array is a list of strings with IPv4 addresses that belong to this
host. They are stored in the normal version (`192.0.2.1`), and can be as many
as required.

#### ipv6
The `ipv6` array is a list of strings with IPv6 addresses that belong to this
host. The shortest format must be used, so `2001:db8::1` will work, but
`2001:0db8:0000:0000:0000:0000:0000:0001` will not. They can be more than one.

### Example Configuration Files
There are example configuration files that include all of the above commands
in this repository. Feel free to start with them as your base, and then make
all necessary changes to them.

## The HTTP API
As previously mentioned, eldim exposes an HTTP API for all servers to upload
data. Here you can find all the currently supported calls to this API:

### GET /
By sending a `GET` request to `/`, eldim will either print some information
about it, or nothing, depending on the value of `servertokens` in the
configuration file.

### POST /api/v1/file/upload/
By sending a `POST` request to `/api/v1/file/upload/`, you can upload files
to eldim. Currently there are two parameters that are required:

#### filename
This is of type `string`, and must contain the desired name of the file.
This can be anything, but spaces or symbols that are not normal for files
are not recommended, since they may not be supported by the Swift backends.

#### file
This `POST` parameter is the actual file. Send the entire file here that has
to be uploaded here.

This API call will return `HTTP 200` and print `Ok` if the upload succeeded.
Any other HTTP Status Code or message is an error.

## How to upload data from a server
You can basically upload files to eldim in any way you like, as long as you
follow the above API, but here are some examples. This code can be for example
in a daily or weekly cron job:

```bash
# Compress nginx' access.log
tar -zcf /tmp/nginx.access.log.tgz /var/log/nginx/access.log /var/log/nginx/access.log.1
# Upload to eldim
curl -F filename=$(date +%F-%H-%M)/access.log -F file=@/tmp/nginx.access.log.tgz https://eldim.example.com/api/v1/file/upload/
```

The `$(date +%F-%H-%M)` part will automatically print the date in the
`2018-01-01-13-37` format (`YYYY-MM-DD-HH-MM`).

If you are testing eldim, you may use `-k` in `curl`, to skip certificate
checks, as you may be using a self-signed certificate. However, deploying
this to production without a trusted certificate is **not** recommended.

For production workloads, you may want to use the `--retry N` flag of `curl`,
to retry the request up to `N` times, if it fails. It is recommended to also
set the `--retry-connrefused` flag as well. You can combine the above with
`--retry-delay X`, so `curl` will sleep `X` seconds between retries. Good
values for `X` are eldim's domain TTL * 2, or something similar.

eldim is designed to work without placing trust on the file upload servers.
If, however, you want to not have to trust the eldim server either, you can
optionally encrypt all data sent to eldim with `gpg`. That way eldim won't
be able to decrypt them, but neither will the sender alone.

To encrypt files with `gpg`, use:

```bash
cat file.tgz | gpg -e -r "recipient@example.com" > out.tgz.enc
```

This requires that you have a key that you trust for `recipient@example.com`.

## eldim Logs
Currently eldim logs a lot of information in detail. This is done on purpose
and is not a debugging leftover. Since it is a tool that is related to
security, it is always good to have a lot of information to be able to go back
to in case something happens.

It is totally normal for eldim to log up to 20 lines per successful upload
request, or even more, depending on the configuration.

During service startup, all information logged is related to actions and
the configuration file, and is in plain text. After the service is started,
all logs start with a UUID. This is called the Request ID. During the
arrival of every request, eldim generated a unique identifier for this
request. This identifier is included in every future log file entry that
is related to this request.

By default eldim logs to `stdout` and `stderr`, so if you are using the
provided `systemd` unit file, all its logs will be available in `syslog`.

## Limitations
There are a few known limitations of eldim that will hopefully be resolved
in future versions. The most notable ones are:

### High RAM Usage
Due to the way the encryption function and the data upload function works,
each uploaded file may exist in memory one or two times. That means that if
you upload a 100 MB file, this request alone may need up to 200 MB of RAM
to be served. There are some small optimizations to generally require only
one copy of the file in memory, but right now for a few ms / sec two copies
may exist at the same time.

This is the most serious limitation of eldim. It can limit the number of
parallel requests very quickly, depending on the server RAM and the file
sizes.

### Many Swift API Calls
Although it does not seem to be a problem with most OpenStack Swift backends,
since all API calls are authenticated, eldim makes too many of them, and it
may be rate limited by some defensive mechanism of the backend.

It can make up to 10 API calls per file upload request, in order to be able
to ensure that it can function properly. However, some optimizations are
currently possible, but they have not been implemented since it does not seem
to affect many cloud providers, adds complexity, and may reduce in more
errors if something is not handled properly.

### Symmetric Encryption
Since encryption is symmetric, the key to decrypt all files must always be
stored in the eldim configuration file. If the eldim server is hacked,
attackers may be able to obtain this and be able to decrypt all backups. This
can be a problem since the API keys are also stored in the exact same file,
and can give them access to the files themselves.