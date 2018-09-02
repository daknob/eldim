package main

import (
	"fmt"
)

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
