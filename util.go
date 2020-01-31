package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	p "github.com/prometheus/client_golang/prometheus"
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
getPassName returns the client name for a given Password password. If it is not
found, an error is returned.
*/
func getPassName(password string) (string, error) {

	if password == "" {
		return "", fmt.Errorf("Password was empty. Did not match")
	}

	for _, c := range clients {
		if c.Password == password {
			return c.Name, nil
		}
	}

	return "", fmt.Errorf("Password did not match client database")
}

/*
requestBasicAuth is an HTTP Handler wrapper that will require the passed handler to
be served only if the HTTP Basic Authentication Credentials are correct.
*/
func requestBasicAuth(username, password, realm string, pa p.CounterVec, handler httprouter.Handle) httprouter.Handle {

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
		if !ok {
			pa.With(p.Labels{"success": "false", "error": "HTTP-Basic-Auth-Not-Ok"}).Inc()
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("You need to supply the correct credentials for this page.\n"))
			return
		}
		if subtle.ConstantTimeCompare(PassedUsername[:], RequiredUserNameHash[:]) != 1 {
			pa.With(p.Labels{"success": "false", "error": "Incorrect-Username"}).Inc()
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("You need to supply the correct credentials for this page.\n"))
			return
		}
		if subtle.ConstantTimeCompare(PassedPassword[:], RequiredPasswordHash[:]) != 1 {
			pa.With(p.Labels{"success": "false", "error": "Incorrect-Password"}).Inc()
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("You need to supply the correct credentials for this page.\n"))
			return
		}

		pa.With(p.Labels{"success": "true", "error": ""}).Inc()
		handler(w, r, Params)
	}
}

/*
httpHandlerToHTTPRouterHandler is a function that converts an HTTP Handler to an HTTPRouter Handler, ignoring
the Params field and assuming it is not used
*/
func httpHandlerToHTTPRouterHandler(h http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		h.ServeHTTP(w, r)
	}
}
