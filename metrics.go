package main

import p "github.com/prometheus/client_golang/prometheus"

/* Prometheus Metrics Declarations */
var (
	promReqServed = p.NewCounterVec(
		p.CounterOpts{
			Name: "eldim_http_requests_served",
			Help: "HTTP Requests Served by eldim, with corresponding types and status codes, per path",
		},
		[]string{
			"method",
			"path",
			"status",
		},
	)
	promMetricsAuth = p.NewCounterVec(
		p.CounterOpts{
			Name: "eldim_prometheus_metrics_scrape_auth",
			Help: "HTTP Requests to the Prometheus Metrics Endpoint and their Authentication Status",
		},
		[]string{
			"success",
			"error",
		},
	)
	promFileUpErrors = p.NewCounterVec(
		p.CounterOpts{
			Name: "eldim_file_upload_errors_occured",
			Help: "Types of errors occured during file uploads",
		},
		[]string{
			"error",
		},
	)
	promReqServTimeHist = p.NewHistogram(
		p.HistogramOpts{
			Name:    "eldim_file_upload_request_time",
			Help:    "Histogram of time of successful file uploads to eldim",
			Buckets: p.LinearBuckets(0, 60, 120),
		},
	)
	promClients = p.NewGaugeVec(
		p.GaugeOpts{
			Name: "eldim_loaded_clients",
			Help: "Clients that are allowed to upload files to eldim",
		},
		[]string{
			"type",
		},
	)
	promIPs = p.NewGaugeVec(
		p.GaugeOpts{
			Name: "eldim_loaded_ip_addressess",
			Help: "IP Addressess that are allowed to upload files to eldim",
		},
		[]string{
			"version",
		},
	)
	promBytesUploadedSuc = p.NewCounter(
		p.CounterOpts{
			Name: "eldim_files_uploaded_bytes_successful",
			Help: "Amount of bytes of files uploaded to eldim successfully",
		},
	)
	promBytesUploadedOSS = p.NewCounter(
		p.CounterOpts{
			Name: "eldim_files_uploaded_bytes_swift",
			Help: "Amount of bytes of files uploaded from eldim to OpenStack Swift Backends",
		},
	)
	promClientIDs = p.NewCounterVec(
		p.CounterOpts{
			Name: "eldim_client_id_type",
			Help: "Type of Client Identification used (Password vs IP Address)",
		},
		[]string{
			"type",
		},
	)
	promHostAuths = p.NewCounterVec(
		p.CounterOpts{
			Name: "eldim_host_authentications",
			Help: "Successful authentications to eldim by hostname",
		},
		[]string{
			"hostname",
		},
	)
	promHostUploads = p.NewCounterVec(
		p.CounterOpts{
			Name: "eldim_host_uploads",
			Help: "Successful file uploads to eldim by hostname",
		},
		[]string{
			"hostname",
		},
	)
	promEldimVersion = p.NewGaugeVec(
		p.GaugeOpts{
			Name: "eldim_server_version",
			Help: "Each eldim server returns '1', with the software version as a tag",
		},
		[]string{
			"eldimversion",
		},
	)
)

/* Register Prometheus Metrics */
func registerPromMetrics() {
	/* Initialize Prometheus */
	p.MustRegister(promReqServed)
	p.MustRegister(promMetricsAuth)
	p.MustRegister(promFileUpErrors)
	p.MustRegister(promReqServTimeHist)
	p.MustRegister(promClients)
	p.MustRegister(promIPs)
	p.MustRegister(promBytesUploadedSuc)
	p.MustRegister(promBytesUploadedOSS)
	p.MustRegister(promClientIDs)
	p.MustRegister(promHostAuths)
	p.MustRegister(promHostUploads)
	p.MustRegister(promEldimVersion)
}

/* Update configuration-based Metrics */
func updateConfMetrics() {
	/* Set Prometheus Loaded Clients Metric */
	var v4 float64 = 0
	var v6 float64 = 0
	var pass float64 = 0
	var v4a float64 = 0
	var v6a float64 = 0
	for _, c := range clients {
		if len(c.IPv4()) >= 1 {
			v4++
			v4a += float64(len(c.IPv4()))
		}
		if len(c.IPv6()) >= 1 {
			v6++
			v6a += float64(len(c.IPv6()))
		}
		if c.Password != "" {
			pass++
		}
	}
	promClients.With(p.Labels{"type": "ipv6"}).Set(v6)
	promClients.With(p.Labels{"type": "ipv4"}).Set(v4)
	promClients.With(p.Labels{"type": "password"}).Set(pass)
	promIPs.With(p.Labels{"version": "6"}).Set(v6a)
	promIPs.With(p.Labels{"version": "4"}).Set(v4a)

	/* Set eldim version */
	promEldimVersion.With(p.Labels{"eldimversion": version}).Set(1)
}
