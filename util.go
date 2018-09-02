package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
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

/*
requestBasicAuth is an HTTP Handler wrapper that will require the passed handler to
be served only if the HTTP Basic Authentication Credentials are correct.
*/
func requestBasicAuth(username, password, realm string, handler httprouter.Handle) httprouter.Handle {

	/* Calculate the SHA-256 Hash of the Required Username and Password */
	RequiredUserNameHash := sha256.Sum256([]byte(username))
	RequiredPasswordHash := sha256.Sum256([]byte(password))

	return func(w http.ResponseWriter, r *http.Request, Params httprouter.Params) {

		user, pass, ok := r.BasicAuth()

		/* Calculate the SHA-256 Hash of the Given Username and Password */
		PassedUsername := sha256.Sum256([]byte(user))
		PassedPassword := sha256.Sum256([]byte(pass))

		/*
			subtle.ConstantTimeCompare is used so the username and password comparison take constant time,
			and therefore do not leak information about the length of the password, or allow time-based side
			channel attacks. However, in order to prevent password length guessing, SHA-256 is used, which is
			always a constant size. Calculation of the SHA-256 hash can still be attacked, but isn't as likely,
			since the inputs are constants.
		*/

		if !ok || subtle.ConstantTimeCompare(PassedUsername[:], RequiredUserNameHash[:]) != 1 || subtle.ConstantTimeCompare(PassedPassword[:], RequiredPasswordHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("You need to supply the correct credentials for this page.\n"))
			return
		}

		handler(w, r, Params)
	}
}
