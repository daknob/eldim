package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/daknob/eldim/internal/backend"

	"github.com/daknob/hlog"
	p "github.com/prometheus/client_golang/prometheus"

	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
)

/*
index handles GET requests to /
*/
func index(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	hlog.LogRequest(r)

	/* If it's okay to print information about the software, show some basic info */
	if conf.ServerTokens {
		/* Set the Server HTTP Header */
		w.Header().Set("Server", fmt.Sprintf("eldim %s", version))
		w.Header().Set("Content-Type", "text/plain")

		/* Print eldim information */
		fmt.Fprintf(w, "eldim %s\n", version)
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "GitHub: https://github.com/daknob/eldim/\n")
	} else {
		/* Print only a space to avoid showing an empty reponse error in some browsers */
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, " ")
	}

	promReqServed.With(p.Labels{"method": "GET", "path": "/", "status": "200"}).Inc()
}

/*
v1fileUpload handles POST requests to /api/v1/file/upload/
*/
func v1fileUpload(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	/* Normal HTTP Procedure */
	rid := hlog.LogRequest(r)
	if conf.ServerTokens {
		w.Header().Set("Server", fmt.Sprintf("eldim %s", version))
	}

	/* Start Request Service Timer */
	now := time.Now().Unix()

	/* Get IP Address of Request */
	ipAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logrus.Errorf("%s: failed to parse Remote IP of request: %v", rid, err)
	}

	/* Limit request body size */
	r.Body = http.MaxBytesReader(w, r.Body, conf.MaxUploadSize*1024*1024)

	/* Begin file processing */
	logrus.Printf("%s: parsing upload from %s", rid, ipAddr)
	err = r.ParseMultipartForm(conf.MaxUploadRAM * 1024 * 1024)
	if err != nil {
		if err.Error() == "http: request body too large" {
			logrus.Errorf("%s: upload exceeds maximum size of %d MB", rid, conf.MaxUploadSize)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Upload exceeds maximum allowed size")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "413"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "Upload-Too-Large"}).Inc()
			return
		}
		if err == io.EOF {
			logrus.Errorf("%s: upload cancelled", rid)
		} else {
			logrus.Errorf("%s: unable to parse multipart form: %v", rid, err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Error while processing upload request")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Multipart-Form-Parse-Error"}).Inc()
		return
	}
	defer r.MultipartForm.RemoveAll()
	logrus.Printf("%s: done parsing upload", rid)

	/* Check if the Password supplied is allowed and matches a host */
	hostname, err := getPassName(r.PostFormValue("password"))
	if err != nil {
		/*
			This is the case in which the password that was supplied by
			the user did not match any of the passwords in the database.

			This means we need to do an IP-based check, and try and see
			if this IP Address is allowed as a client.
		*/
		logrus.Printf("%s: client at %s did not supply a known password. Checking by IP", rid, ipAddr)

		hostname, err = getIPName(ipAddr)
		if err != nil {
			logrus.Printf("%s: IP Address %s is not a known client: %v", rid, ipAddr, err)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "IP Address not in access list")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "403"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "IP-Not-Allowed"}).Inc()
			return
		}

		promClientIDs.With(p.Labels{"type": "ipaddr"}).Inc()
	} else {
		promClientIDs.With(p.Labels{"type": "password"}).Inc()
	}

	/* Authentication has happened successfully */
	logrus.Printf("%s: detected Hostname: %s", rid, hostname)
	promHostAuths.With(p.Labels{"hostname": hostname}).Inc()

	/* Check if a file name has been provided */
	if r.PostFormValue("filename") == "" {
		logrus.Errorf("%s: did not provide a file name to save the file as", rid)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "File name not supplied")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Name-Not-Provided"}).Inc()
		return
	}

	/* Connect to all Backends */
	logrus.Printf("%s: connecting to Backends...", rid)
	var backends []backend.Client
	for _, be := range conf.Clients() {
		logrus.Printf("%s: connecting to '%s'", rid, be.Name())

		err := be.Connect(r.Context())
		if err != nil {
			logrus.Errorf("%s: unable to connect to %s Backend '%s': %v", rid, be.BackendName(), be.Name(), err)
			promFileUpErrors.With(p.Labels{
				"error": fmt.Sprintf(
					"%s-Backend-Connection-Error",
					strings.ReplaceAll(be.BackendName(), " ", "-"),
				),
			}).Inc()
			continue
		}
		logrus.Printf("%s: successfully connected to %s Backend: %s", rid, be.BackendName(), be.Name())
		backends = append(backends, be)
	}

	if len(backends) == 0 {
		logrus.Errorf("%s: no Backends available to handle requests", rid)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "An error occured while processing the uploaded file")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "No-Backends-Available"}).Inc()
		return
	}
	logrus.Printf("%s: connection successful. %d Backends live.", rid, len(backends))

	/* Check if file exists in all available containers */
	logrus.Printf("%s: checking if file exists already in any Backend...", rid)
	for _, be := range backends {
		exists, err := be.ObjectExists(r.Context(), fmt.Sprintf("%s/%s", hostname, r.PostFormValue("filename")))
		if err != nil {
			logrus.Errorf("%s: failed to check if object exists for backend %s: %v", rid, be.Name(), err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "An error occured while processing the uploaded file")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "Error-Check-If-Object-Exists-In-Backend"}).Inc()
			return
		}
		if exists {
			logrus.Errorf("%s: file '%s' already exists", rid, r.PostFormValue("filename"))
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "File already exists.")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "File-Already-Exists"}).Inc()
			return
		}
	}
	logrus.Printf("%s: file does not exist in any Backend.", rid)

	/* Process uploaded file */
	file, _, err := r.FormFile("file")
	if err != nil {
		logrus.Errorf("%s: uploaded File Error: %v", rid, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Did not supply a valid file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Invalid-Or-Missing"}).Inc()
		return
	}

	/*
	 * Determine the uploaded file size in bytes
	 * In this case "file" is not an *os.File, unless it did not
	 * fit in memory and had to be written to disk. So using stat
	 * to determine the size is not reliable. We have to use seek
	 * instead, and then restore to the beginning of the file.
	 */
	uploadSize, err := file.Seek(0, os.SEEK_END)
	if err != nil {
		logrus.Fatalf("failed to get file size: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "An error occurred while processing the uploaded file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Seek-To-End-Failed"}).Inc()
		return
	}

	_, err = file.Seek(0, os.SEEK_SET)
	if err != nil {
		logrus.Fatalf("failed to get file size: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "An error occurred while processing the uploaded file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Seek-To-Start-Failed"}).Inc()
		return
	}

	logrus.Printf("%s: file uploaded. Size: %d bytes.", rid, uploadSize)
	promBytesUploadedSuc.Add(float64(uploadSize))
	logrus.Printf("%s: encrypting file...", rid)

	/* Load all Recipients from configuration */
	var rcpt []age.Recipient
	for _, r := range conf.Encryption.AgeID {
		ar, err := age.ParseX25519Recipient(r)
		if err != nil {
			logrus.Errorf("%s: failed to parse age ID Recipient: %v", rid, err)
			continue
		}
		rcpt = append(rcpt, age.Recipient(ar))
	}
	for _, r := range conf.Encryption.AgeSSH {
		ar, err := agessh.ParseRecipient(r)
		if err != nil {
			logrus.Errorf("%s: failed to parse age SSH Recipient: %v", rid, err)
			continue
		}
		rcpt = append(rcpt, age.Recipient(ar))
	}

	if len(rcpt) == 0 {
		logrus.Errorf("%s: no recipients could be parsed from the configuration file", rid)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "No-Valid-Age-Recipients-Found"}).Inc()
		return
	}

	/* Initialize age for encryption */
	encBuff := &bytes.Buffer{}

	ew, err := age.Encrypt(encBuff, rcpt...)
	if err != nil {
		logrus.Errorf("%s: failed to initialize encryption: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Initialize-Age-Encryption"}).Inc()
		return
	}

	/* Encrypt file */
	wb, err := io.Copy(ew, file)
	if err != nil || wb != uploadSize {
		logrus.Errorf("%s: encryption failed, expected %d bytes ciphertext, got %d: %v", rid, uploadSize, wb, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Encrypt-File"}).Inc()
		return
	}

	if ew.Close() != nil {
		logrus.Errorf("%s: encryption failed: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Encrypt-File-Close"}).Inc()
		return
	}

	encrSize := int64(encBuff.Len())

	logrus.Printf("%s: encryption completed", rid)
	logrus.Printf("%s: uploading encrypted file to all Backends...", rid)

	/* All files are <hostname>/<desired_name> */
	uploadFileName := fmt.Sprintf("%s/%s", hostname, r.PostFormValue("filename"))
	/* Counts successful uploads */
	uploads := 0

	/* For every backend */
	for _, be := range backends {
		logrus.Printf("%s: uploading %s to %s", rid, uploadFileName, be.Name())

		err := be.UploadFile(context.Background(), uploadFileName, bytes.NewReader(encBuff.Bytes()), encrSize)
		if err != nil {
			logrus.Errorf("%s: failed to upload %s to %s: %v", rid, uploadFileName, be.Name(), err)
			promFileUpErrors.With(p.Labels{
				"error": fmt.Sprintf(
					"%s-Upload-Failed", strings.ReplaceAll(be.BackendName(), " ", "-"),
				),
			}).Inc()
		} else {
			uploads++
			promBytesUploaded.With(
				p.Labels{"backendtype": strings.ReplaceAll(be.BackendName(), " ", "-")},
			).Add(float64(encrSize))
		}

		/* Disconnect from Backend */
		be.Disconnect(r.Context())
	}

	/* Reset the file buffer */
	encBuff.Reset()

	/* Check if at least one file was uploaded */
	if uploads == 0 {
		logrus.Errorf("%s: did not manage to upload to any Backends!", rid)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to store file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "All-Uploads-Failed"}).Inc()
		return
	}

	/* All good, finally it's over */
	logrus.Printf("%s: uploaded encrypted file to %d Backends", rid, uploads)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Ok")

	/* Update Prometheus on the successful request handling */
	promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "200"}).Inc()
	promReqServTimeHist.Observe(float64(time.Now().Unix() - now))
	promHostUploads.With(p.Labels{"hostname": hostname}).Inc()

}
