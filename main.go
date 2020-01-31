package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	p "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

var (
	conf    config
	clients []clientInfo
)

/* Prometheus Metrics */
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
)

const (
	version = "v0.3.2"
)

func main() {

	/* Output logs in JSON or Text */
	logFormat := flag.Bool("j", false, "Output logs in JSON")

	/* Configuration File Path */
	configPath := flag.String("c", "/etc/eldim/eldim.yml", "Path to the configuration file")

	/* Parse flags */
	flag.Parse()

	/* Set the log format to JSON if requested */
	if *logFormat == true {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{})
	}

	/* Startup logs */
	logrus.Printf("Starting eldim...")
	logrus.Printf("Log in JSON: %v", *logFormat)
	logrus.Printf("Configuration File: %s", *configPath)

	/* Parse the configuration file */
	logrus.Printf("Parsing the configuration file...")

	/* Open the configuration file, and read contents to RAM */
	confb, err := ioutil.ReadFile(*configPath)
	if err != nil {
		logrus.Fatalf("Could not open configuration file: %v", err)
	}

	/* Attempt to parse it for YAML */
	err = yaml.Unmarshal(confb, &conf)
	if err != nil {
		logrus.Fatalf("Could not parse the YAML configuration file: %v", err)
	}

	logrus.Printf("Configuration file loaded.")

	/* Validate configuration by appropriate function call */
	logrus.Printf("Validating parameters...")
	err = validateConfig(conf)
	if err != nil {
		logrus.Fatalf("Invalid configuration: %v", err)
	}
	logrus.Printf("Configuration file validated.")

	/* Load client file */
	clib, err := ioutil.ReadFile(conf.ClientFile)
	if err != nil {
		logrus.Fatalf("Could not open clients file: %v", err)
	}
	err = yaml.Unmarshal(clib, &clients)
	if err != nil {
		logrus.Fatalf("Could not parse clients YML file: %v", err)
	}

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

	/* Set Prometheus Loaded Clients Metric */
	var v4 float64 = 0
	var v6 float64 = 0
	var pass float64 = 0
	var v4a float64 = 0
	var v6a float64 = 0
	for _, c := range clients {
		if len(c.Ipv4) >= 1 {
			v4++
			v4a += float64(len(c.Ipv4))
		}
		if len(c.Ipv6) >= 1 {
			v6++
			v6a += float64(len(c.Ipv6))
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

	/* Various web server configurations */
	logrus.Printf("Configuring the HTTP Server...")

	/* Create an HTTP Router */
	router := httprouter.New()
	router.GET("/", index)
	router.POST("/api/v1/file/upload/", v1fileUpload)

	/* Only enable Prometheus metrics if configured */
	if conf.PrometheusEnabled {
		router.GET(
			"/metrics",
			requestBasicAuth(
				conf.PrometheusAuthUser,
				conf.PrometheusAuthPass,
				"Prometheus Metrics",
				*promMetricsAuth,
				httpHandlerToHTTPRouterHandler(
					promhttp.Handler(),
				),
			),
		)
	}

	/* Configure TLS */
	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
	}

	/* Configure HTTP */
	server := http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       180 * time.Second,
		TLSConfig:         tlsConfig,
		Handler:           router,
		Addr:              fmt.Sprintf(":%d", conf.ListenPort),
	}

	logrus.Printf("HTTP Server Configured.")

	/* Start serving TLS */
	logrus.Printf("Serving on :%d ...", conf.ListenPort)

	err = server.ListenAndServeTLS(
		conf.TLSChainPath,
		conf.TLSKeyPath,
	)
	if err != nil {
		logrus.Fatalf("Failed to start HTTP Server: %v", err)
	}

	/* Exit */
	logrus.Printf("eldim quitting...")

}
