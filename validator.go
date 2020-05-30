package main

import (
	"fmt"
	"io/ioutil"
	"net"
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
			return fmt.Errorf("Expire seconds cannot be negative for backend '%s' [%d]", be.Name, n)
		}
		if be.ExpireSeconds == 0 {
			logrus.Warnf("You did not request file expiry for backend '%s'", be.Name)
		} else {
			logrus.Warnf("You requested that all files on backend '%s' be deleted after %d seconds", be.Name, be.ExpireSeconds)
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

	/*
		For this part, since the Clients File is a separate file, we are using
		a separate function, that will validate only the Clients file.
	*/

	err = validateClientsFile(conf.ClientFile)
	if err != nil {
		return fmt.Errorf("Failed to validate Clients File: %v", err)
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

/*
validateClientsFile will validate the clients file that is passed and will
return an error if something invalid is found. It may also log various warnings
but it will not return an error in that case.
*/
func validateClientsFile(cfile string) error {

	/* Check if a Clients File has been even configured */
	if cfile == "" {
		return fmt.Errorf("Did not supply clients file")
	}

	/* Attempt to read the Clients File */
	fc, err := ioutil.ReadFile(cfile)
	if err != nil {
		return fmt.Errorf("Failed to open clients file: %v", err)
	}

	/* Unmarshal the YAML Clients File */
	var clients []clientInfo

	err = yaml.Unmarshal(fc, &clients)
	if err != nil {
		return fmt.Errorf("Unable to decode client file YAML: %v", err)
	}

	/* Check if clients have been supplied */
	if len(clients) == 0 {
		return fmt.Errorf("No clients have been supplied. eldim will not work")
	}

	/* Loop through all the clients in the client file */
	for i := 0; i < len(clients); i++ {
		c := clients[i]

		/* Check if all clients have names */
		if c.Name == "" {
			return fmt.Errorf("Client %d has no name in Client File", i+1)
		}

		/* Ensure there aren't any duplicate names, IPs, passwords */
		for j := i + 1; j < len(clients); j++ {
			/* Check name */
			if c.Name == clients[j].Name {
				return fmt.Errorf(
					"Clients %d and %d have the same name",
					i+1, j+1,
				)
			}

			/* Check for common IP Addresses */

			/*
				NOTE: A clever user may attempt to enter an IPv4 Address in one
				of the IPv4 host arrays, and an IPv6-equivalent of the IPv4
				Address in one of the IPv6 arrays. If we just compared the IPv4
				Address and the IPv6 slices separately, this could bypass this
				check. For this reason, we are joining the IPv4 and IPv6 Arrays
				and then using the Equals function of the IP object, which,
				explicitly, in its documentation, mentions that will be able to
				flag them as equal. This also reduces the code.
			*/

			currentHostIPs := append(c.Ipv4, c.Ipv6...)
			nextHostIPs := append(clients[j].Ipv4, clients[j].Ipv6...)

			/* Run a quick check to ensure the address are not common */
			for _, cip := range currentHostIPs {

				/* Ensure the current IP is valid */
				cipaddr := net.ParseIP(cip)
				if cipaddr == nil {
					return fmt.Errorf(
						"Client '%s' (%d) does not have valid IP: '%s'",
						c.Name, i+1,
						cip,
					)
				}

				for _, nip := range nextHostIPs {
					/* Ensure the next IP is valid */
					nipaddr := net.ParseIP(nip)
					if nipaddr == nil {
						return fmt.Errorf(
							"Client '%s' (%d) does not have valid IP: '%s'",
							clients[j].Name, j+1,
							nip,
						)
					}

					/* Ensure IPs are not equal */
					if cipaddr.Equal(nipaddr) {
						return fmt.Errorf(
							"Clients '%s' and '%s' (%d,%d) have a common IP: %s",
							c.Name, clients[j].Name,
							i+1, j+1,
							cipaddr.String(),
						)
					}
				}
			}

			/* Check for common Passwords */
			if c.Password == clients[j].Password {
				return fmt.Errorf(
					"Clients '%s' and '%s' (%d,%d) have the same password",
					c.Name, clients[j].Name,
					i+1, j+1,
				)
			}
		}

		/*
			Check if IPv4 Addresses are in the IPv4 Array and if IPv6 Addresses
			are in the IPv6 Array. Note that we have already verified the items
			are valid IPs, so we can be a bit loose on our checks. The check is
			also a bit more loose on purpose on the IPv6 part, so people who
			don't want to separate the addresses between families can enter
			everything in IPv6.
		*/
		for _, v4 := range c.Ipv4 {
			if !regexp.MustCompile("^\\d+\\.\\d+\\.\\d+\\.\\d+$").MatchString(v4) {
				return fmt.Errorf(
					"IP '%s' in host '%s' (%d) is not an IPv4 Address",
					v4, c.Name, i+1,
				)
			}
		}
		for _, v6 := range c.Ipv6 {
			if !regexp.MustCompile(":").MatchString(v6) {
				return fmt.Errorf(
					"IP '%s' in host '%s' (%d) is not an IPv6 Address",
					v6, c.Name, i+1,
				)
			}
		}

		/*
			Check if for every client there exists at least one of (IPv6, IPv4,
			Password), otherwise this client cannot authenticate.
		*/
		if c.Password == "" && len(c.Ipv4) == 0 && len(c.Ipv6) == 0 {
			return fmt.Errorf(
				"Client '%s' does not have an authentication method: IP or Password required",
				c.Name,
			)
		}

		/* Enforce password policy */
		if c.Password != "" {
			if len(c.Password) < 32 {
				return fmt.Errorf(
					"Client '%s' (%d) has a short password",
					c.Name, i+1,
				)
			}

			if len(c.Password) > 128 {
				return fmt.Errorf(
					"Client '%s' (%d) has a too long password",
					c.Name, i+1,
				)
			}
		}
	}

	/* Hopefully no errors have occured */
	return nil

}
