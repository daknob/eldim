package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/ncw/swift"
	yaml "gopkg.in/yaml.v2"

	"github.com/sirupsen/logrus"
)

/*
validateConfig will validate the configuration file that is passed and will
return an error if something invalid is found. It may also log various
warnings but it will not return an error in that case.
*/
func validateConfig(conf config) error {

	/* Validate Listening Port */
	if conf.ListenPort < 0 {
		return fmt.Errorf("TCP Listening Port must be positive number")
	}
	if conf.ListenPort < 1024 {
		logrus.Warnf("TCP Listening Port below 1024. Ensure you have permissions")
	}
	if conf.ListenPort > 65535 {
		return fmt.Errorf("TCP Listening Port must be below 65535")
	}

	/* Validate TLS Chain File */
	if conf.TLSChainPath == "" {
		return fmt.Errorf("TLS Chain File is required. eldim works only with HTTPS")
	}
	f, err := os.Open(conf.TLSChainPath)
	if err != nil {
		return fmt.Errorf("Failed to open TLS Chain File: %v", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("Failed to close TLS Chain File: %v", err)
	}

	/* Validate TLS Key File */
	if conf.TLSKeyPath == "" {
		return fmt.Errorf("TLS Key File is required. eldim works only with HTTPS")
	}
	f, err = os.Open(conf.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("Failed to open TLS Key File: %v", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("Failed to close TLS Key File: %v", err)
	}

	/* Validate Server Tokens */

	/* Validate Swift Backends */
	if len(conf.SwiftBackends) == 0 {
		return fmt.Errorf("eldim requires Swift Backends configured to upload files")
	}

	for n, be := range conf.SwiftBackends {
		if be.Apikey == "" || be.AuthURL == "" || be.Region == "" || be.Username == "" || be.Container == "" {
			return fmt.Errorf("All fields are required for Swift Backends to work")
		}
		if be.Name == "" {
			logrus.Warnf("Backend #%d does not have a name. It is encouraged to add one so you can find relevant errors easier in the logs.", n)
		}
		if be.ExpireSeconds < 0 {
			return fmt.Errorf("Expire seconds cannot be negative for backend \"%s\" [%d]", be.Name, n)
		}
		if be.ExpireSeconds == 0 {
			logrus.Warnf("You did not request file expiry for backend \"%s\"", be.Name)
		} else {
			logrus.Warnf("You requested that all files on backend \"%s\" be deleted after %d seconds", be.Name, be.ExpireSeconds)
		}

		osConn := swift.Connection{
			UserName:     be.Username,
			ApiKey:       be.Apikey,
			AuthUrl:      be.AuthURL,
			Domain:       "default",
			Region:       be.Region,
			AuthVersion:  3,
			EndpointType: swift.EndpointTypePublic,
		}

		err := osConn.Authenticate()

		if err != nil {
			return fmt.Errorf("Swift Backend Authentication Error: Backend %s (%d): %v", be.Name, n, err)
		}

		_, _, err = osConn.Container(be.Container)

		if err != nil {
			return fmt.Errorf("Swift Backend Container Error: Backend %s (%d): Container: %s: %v", be.Name, n, be.Container, err)
		}

		osConn.UnAuthenticate()
	}

	/* Validate Client File */
	cfile, err := ioutil.ReadFile(conf.ClientFile)
	if err != nil {
		return fmt.Errorf("Unable to read clients file: %v", err)
	}

	var clients []clientInfo
	err = yaml.Unmarshal(cfile, &clients)
	if err != nil {
		return fmt.Errorf("Unable to decode client file YAML: %v", err)
	}

	/* Validate Max Upload RAM (in MB) */
	if conf.MaxUploadRAM <= 0 {
		return fmt.Errorf("Maximum Upload RAM must be a positive number")
	}
	if conf.MaxUploadRAM < 100 {
		logrus.Warnf("It is recommended to use at least 100 MB of RAM for uploads")
	}

	/* Validate Temporary Upload Path */
	if conf.TempUploadPath == "" {
		return fmt.Errorf("You must supply a temporary upload path for uploaded files")
	}
	f, err = os.Create(fmt.Sprintf("%s/tmp", conf.TempUploadPath))
	if err != nil {
		return fmt.Errorf("Error writing files to the temporary upload path: %v", err)
	}
	f.Close()
	err = os.Remove(fmt.Sprintf("%s/tmp", conf.TempUploadPath))
	if err != nil {
		return fmt.Errorf("Error deleting file from the temporary upload path: %v", err)
	}

	/* Validate Encryption Key */
	if conf.EncryptionKey == "" {
		return fmt.Errorf("You must supply an encryption key to encrypt all uploaded files")
	}
	if len(conf.EncryptionKey) < 16 {
		return fmt.Errorf("You must supply an encryption key of at least 16 characters")
	}
	if len(conf.EncryptionKey) < 30 {
		logrus.Warnf("The encryption key set is less than 30 characters. It may not be so secure")
	}

	/* Validate Prometheus Settings */
	if conf.PrometheusEnabled == true {
		/* Only check Prometheus Configuration if Prometheus is enabled */
		if conf.PrometheusAuthUser == "" {
			return fmt.Errorf("You need to set the prometheusauthuser in the configuration file. eldim only works with HTTP Basic Auth for Prometheus Metrics")
		}
		if !regexp.MustCompile("^[a-zA-Z0-9]{20,128}$").MatchString(conf.PrometheusAuthUser) {
			return fmt.Errorf("The prometheusauthuser must contain a-z, A-Z, and 0-9, and must be 20-128 characters long")
		}
		if conf.PrometheusAuthPass == "" {
			return fmt.Errorf("You need to set the prometheusauthpass in the configuration file. eldim only works with HTTP Basic Auth for Prometheus Metrics")
		}
		if !regexp.MustCompile("^[a-zA-Z0-9]{20,128}$").MatchString(conf.PrometheusAuthPass) {
			return fmt.Errorf("The prometheusauthpass must contain a-z, A-Z, and 0-9, and must be 20-128 characters long")
		}
	}

	return nil
}
