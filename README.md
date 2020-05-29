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
sudo useradd -s /usr/sbin/nologin -r -M eldim
```

When executed, eldim has two command line flags that you can use to configure
it before it even reads the configuration file. They are:

* `-j`: When set, it will output all logs in JSON format, instead of plaintext
* `-c`: The path to the configuration file

## Metrics
As of `eldim v0.2.0`, eldim supports metrics exporting using
[Prometheus](https://prometheus.io/). You can find more information about the
metrics currently supported and exported [here](docs/metrics.md).

## Configuration
In order to read the full documentation on how to configure `eldim`, click
[here](docs/config.md).

## The HTTP API
You can find the full specification of the HTTP API of `eldim` by clicking
[here](docs/api.md).

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
