package main

import (
	"fmt"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/google/uuid"
)

/*
logRequest will create a new Request ID, log the incoming request, and then
return the Request ID for future usage.
*/
func logRequest(r *http.Request) string {
	rid := uuid.New().String()
	logrus.Printf("%s: %s \"%s %s %s\" \"%s\" \"%s\"", rid, r.RemoteAddr, r.Method, r.RequestURI, r.Proto, r.Referer(), r.Host)
	return rid
}

/*
getIPName returns the client name of a given IP Address ip. If it is not found,
an error is returned.
*/
func getIPName(ip string) (string, error) {
	for _, c := range clients {
		for _, v4 := range c.Ipv4 {
			if v4 == ip {
				return c.Name, nil
			}
		}
		for _, v6 := range c.Ipv6 {
			if v6 == ip {
				return c.Name, nil
			}
		}
	}

	return "", fmt.Errorf("IP Address not a client")
}
