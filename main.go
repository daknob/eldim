package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"net/http"
	"time"

	"github.com/daknob/eldim/config"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v3"
)

var (
	conf    config.Config
	clients []config.ClientConfig
)

const (
	version = "v0.6.2"
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
	logrus.Printf("starting eldim...")
	logrus.Printf("log in JSON: %v", *logFormat)
	logrus.Printf("configuration file: %s", *configPath)

	/* Parse the configuration file */
	logrus.Printf("parsing the configuration file...")

	/* Open the configuration file, and read contents to RAM */
	confb, err := os.ReadFile(*configPath)
	if err != nil {
		logrus.Fatalf("could not open configuration file: %v", err)
	}

	/* Attempt to parse it for YAML */
	err = yaml.Unmarshal(confb, &conf)
	if err != nil {
		logrus.Fatalf("could not parse the YAML configuration file: %v", err)
	}

	logrus.Printf("configuration file loaded.")

	/* Validate configuration by appropriate function call */
	logrus.Printf("validating parameters...")
	err = conf.Validate()
	if err != nil {
		logrus.Fatalf("invalid configuration: %v", err)
	}
	logrus.Printf("configuration file validated.")

	/* Load client file */
	clib, err := os.ReadFile(conf.ClientFile)
	if err != nil {
		logrus.Fatalf("could not open clients file: %v", err)
	}
	err = yaml.Unmarshal(clib, &clients)
	if err != nil {
		logrus.Fatalf("could not parse clients YML file: %v", err)
	}

	/* Register Prometheus Metrics */
	registerPromMetrics()

	/* Update configuration-based Metrics */
	updateConfMetrics()

	/* Various web server configurations */
	logrus.Printf("configuring the HTTP Server...")

	/* Create an HTTP Router */
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", index)
	mux.HandleFunc("POST /api/v1/file/upload/", v1fileUpload)

	/* Only enable Prometheus metrics if configured */
	if conf.PrometheusEnabled {
		mux.HandleFunc(
			"GET /metrics",
			requestBasicAuth(
				conf.PrometheusAuthUser,
				conf.PrometheusAuthPass,
				"Prometheus Metrics",
				*promMetricsAuth,
				promhttp.Handler().ServeHTTP,
			),
		)
	}

	/* Configure TLS */
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	/* Configure HTTP */
	server := http.Server{
		ReadTimeout:       time.Duration(conf.ReadTimeout) * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       180 * time.Second,
		TLSConfig:         tlsConfig,
		Handler:           mux,
		Addr:              fmt.Sprintf(":%d", conf.ListenPort),
	}

	logrus.Printf("HTTP Server Configured.")

	/* Start serving TLS */
	logrus.Printf("serving on :%d ...", conf.ListenPort)

	err = server.ListenAndServeTLS(
		conf.TLSChainPath,
		conf.TLSKeyPath,
	)
	if err != nil {
		logrus.Fatalf("failed to start HTTP Server: %v", err)
	}

	/* Exit */
	logrus.Printf("eldim quitting...")

}
