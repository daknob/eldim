package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/daknob/eldim/config"

	"github.com/prometheus/client_golang/prometheus/promhttp"

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

	/* Set up structured logging */
	var handler slog.Handler
	if *logFormat {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(handler))

	/* Startup logs */
	slog.Info("starting eldim", "version", version)
	slog.Info("configuration",
		"json_logs", *logFormat,
		"config_file", *configPath,
	)

	/* Parse the configuration file */
	slog.Info("parsing configuration file")

	/* Open the configuration file, and read contents to RAM */
	confb, err := os.ReadFile(*configPath)
	if err != nil {
		slog.Error("could not open configuration file", "path", *configPath, "error", err)
		os.Exit(1)
	}

	/* Attempt to parse it for YAML */
	err = yaml.Unmarshal(confb, &conf)
	if err != nil {
		slog.Error("could not parse YAML configuration file", "path", *configPath, "error", err)
		os.Exit(1)
	}

	slog.Info("configuration file loaded")

	/* Validate configuration by appropriate function call */
	slog.Info("validating parameters")
	err = conf.Validate()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	slog.Info("configuration file validated")

	/* Load client file */
	clib, err := os.ReadFile(conf.ClientFile)
	if err != nil {
		slog.Error("could not open clients file", "path", conf.ClientFile, "error", err)
		os.Exit(1)
	}
	err = yaml.Unmarshal(clib, &clients)
	if err != nil {
		slog.Error("could not parse clients YAML file", "path", conf.ClientFile, "error", err)
		os.Exit(1)
	}
	slog.Info("clients file loaded", "clients", len(clients))

	/* Register Prometheus Metrics */
	registerPromMetrics()

	/* Update configuration-based Metrics */
	updateConfMetrics()

	/* Various web server configurations */
	slog.Info("configuring HTTP server")

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

	slog.Info("HTTP server configured",
		"port", conf.ListenPort,
		"read_timeout_s", conf.ReadTimeout,
		"tls_chain", conf.TLSChainPath,
		"prometheus", conf.PrometheusEnabled,
	)

	/* Start serving TLS */
	slog.Info("starting TLS listener", "port", conf.ListenPort)

	err = server.ListenAndServeTLS(
		conf.TLSChainPath,
		conf.TLSKeyPath,
	)
	if err != nil {
		slog.Error("failed to start HTTP server", "error", err)
		os.Exit(1)
	}

	/* Exit */
	slog.Info("eldim quitting")

}
