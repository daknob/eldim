# Configuration

This document covers all the configuration options for eldim. There is a main
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

#### prometheusenabled
The `prometheusenabled` is a boolean value. If it has the value `true`, it
enabled exporting of Prometheus metrics. If it's `false` (default if missing),
then Prometheus metrics export is disabled.

#### prometheusauthuser
The `prometheusauthuser` is a string that includes the HTTP Basic Auth Username
for the Prometheus metrics endpoint (`/metrics`). It needs to be a-z, A-Z, 0-9,
and 20-128 characters long, for security reasons.

#### prometheusauthpass
The `prometheusauthpass` is a string that contains the HTTP Basic Auth Password
for the Prometheus metrics endpoint (`/metrics`). It needs to be a-z, A-Z, 0-9,
and 20-128 characters long, for security reasons.

#### swiftbackends
The `swiftbackends` is an array, which contains a list of all OpenStack Swift
backends that eldim will upload data to. More than one data storage is
supported, but if you add too many it may take excessive amounts of bandwidth
and time to complete the operations.

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

#### gcsbackends
The `gcsbackends` is an array that contains a list of all Google Cloud Storage
backends that eldim will upload data to. You can specify more than one backend
if you want, such as one per region. Unlike the `swiftbackends`, this does not
support `eldim`-based file expiration and instead it must be configured from
the Google Cloud Console. There you can find a much more flexible way which
also includes storage class options, and gives you the ability to keep files
in hot storage for 30 days, and then progressively move to colder and colder
storage types, until their eventual deletion.

The fields of each array element are:

##### name
The `name` parameter is a friendly name that you set to identify this backend
in eldim's logs, as well as its configuration file. It can be any string.

##### bucketname
The `bucketname` parameter is the Google Cloud Storage bucket's name that you
intend to upload all the data to. This must already exist and be configured
before you start using it.

##### credsfile
The `credsfile` parameter includes the full path to the location of your
service account's Google Cloud Storage credentials. It should be a JSON file
that contains inside it all the information needed for eldim to establish a
connection and authenticate properly. You can obtain this file by going to
*IAM & Admin* in Google Cloud Console, clicking *Service Accounts*, and then
creating one. When prompted, download the JSON secret file, and use this to
deploy eldim with.

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

#### password
The `password` string is a password that can be supplied by the `password` POST
form element that can be used to lookup clients instead of by their IP Address.
The `password` is checked before the IP Address of the host. For security
reasons, the field **must** be between 32 and 128 characters in size.

### Example Configuration Files
There are example configuration files that include all of the above commands
in this repository. Feel free to start with them as your base, and then make
all necessary changes to them.
