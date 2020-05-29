# Metrics

As of `eldim v0.2.0`, eldim supports metrics exporting using
[Prometheus](https://prometheus.io/). In
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

### Prometheus Metrics HTTP Basic Auth
eldim exports `eldim_prometheus_metrics_scrape_auth`, which is a counter
vector, and measures successful or unsuccessful scrapes of the Prometheus
endpoint, based on their HTTP Basic Authentication Check. Through this you
can monitor successful scrapes, scrape attempts without HTTP Basic Auth
provided, as well as incorrect username or password attempts. It exposes
the following labels:

#### success
Set to `true` or `false` depending on whether the scrape was successful.

#### error
Set to `HTTP-Basic-Auth-Not-Ok` during errors with HTTP Basic Auth, such as
when no credentials were supplied, to `Incorrect-Username` when the username
provided by the user is incorrect, or to `Incorrect-Password` when the password
supplied is not correct.

### File Upload Error Metrics
eldim exports `eldim_file_upload_errors_occured`, which is a counter vector,
and essentially counts all errors occured during file upload requests. You
can use this to see what errors come up, or if there is a spike in errors
recently, an in coordination with `eldim_http_requests_served` identify
problems in your eldim setup.

### Successful File Upload Time Histogram
eldim exports `eldim_file_upload_request_time`, which is a histogram of the
time it took to successfully serve a file upload request. The request time is
measured in seconds, and the buckets are one for every minute, up to two hours.

### Available Clients
eldim exports `eldim_loaded_clients`, which is a gauge vector that contains
how many clients are available and loaded from the configuration file to the
system and have `ipv6` and `ipv4` addressess. This metric only changes when
the configuration file is loaded, but can be useful to track historical changes
in `eldim` hosts. This field may also contain `password` for clients that are
being identified by a password.
eldim also exports `eldim_loaded_ip_addressess`, which is a gauge vector,
containing information on how many IP addressess, and their version (`6`/`4`),
have been loaded to `eldim`. Like above, this is only loaded when the
`clients.yml` file is loaded, so it's also used for mostly historical reasons.

### Uploaded Bytes
eldim exports `eldim_files_uploaded_bytes_successful`, which is a gauge,
whose value contains the total amount of bytes since eldim launch that have
been successfully uploaded and processed by eldim. This includes the sum of
the size of all files uploaded **to** eldim.
In addition to that, there's also `eldim_files_uploaded_bytes_swift`, which
includes the total amount of bytes that **eldim** uploaded, to OpenStack
Swift backends. This number is different than the previous once since it
includes encryption overhead, as well as the possibility of multiple OpenStack
Swift backends, causing more data to be uploaded.

### Client Identification Type
eldim exports `eldim_client_id_type`, which is a counter vector, with the
following label:

#### type
The `type` label contains the type of each successful authentication done
against `eldim`. It contains two possible values: `ipaddr` and `password`. The
first value is assigned every time a successful authentication is performed
with an IP Address, and the second is assigned every time a successful
authentication is performed with a password.

### Successful Authentications by Host Name
eldim exports `eldim_host_authentications`, which is a counter vector, counting
how many successful authentication attempts have happened so far, with the
following label:

#### hostname
The `hostname` label contains the host name that has performed the
authentication successfully.

### Successful File Uploads by Host Name
eldim exports `eldim_host_uploads`, which is a counter vector, counting how
many successful file uploads have happened so far, with the following label:

#### hostname
The `hostname` label contains the host name that has performed the successful
file upload.

### Default Prometheus for Go Metrics
The Prometheus Client Library for Go exports a heap of metrics by default,
which include, among others, Go Garbage Collection metrics, Goroutine Info,
Go compiler version, Application Memory Info, Running Threads, as well as
Exporter Info, such as how many times the application data has been scraped
by Prometheus.
