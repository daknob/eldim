package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/daknob/eldim/internal/backend"

	p "github.com/prometheus/client_golang/prometheus"
)

/* currentUploads tracks file names currently being processed by this instance */
var currentUploads sync.Map

/*
index handles GET requests to /
*/
func index(w http.ResponseWriter, r *http.Request) {
	rid := generateRequestID()
	log := slog.With("request_id", rid)

	log.Info("request received",
		slog.Group("request",
			"method", r.Method,
			"uri", r.RequestURI,
			"proto", r.Proto,
			"host", r.Host,
		),
		slog.Group("client",
			"remote_addr", r.RemoteAddr,
			"x_forwarded_for", r.Header.Get("X-Forwarded-For"),
			"user_agent", r.UserAgent(),
		),
	)

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
	log.Info("request completed", "status", 200)
}

/*
v1fileUpload handles POST requests to /api/v1/file/upload/
*/
func v1fileUpload(w http.ResponseWriter, r *http.Request) {
	rid := generateRequestID()
	log := slog.With("request_id", rid)

	log.Info("request received",
		slog.Group("request",
			"method", r.Method,
			"uri", r.RequestURI,
			"proto", r.Proto,
			"host", r.Host,
			"content_length", r.ContentLength,
		),
		slog.Group("client",
			"remote_addr", r.RemoteAddr,
			"x_forwarded_for", r.Header.Get("X-Forwarded-For"),
			"user_agent", r.UserAgent(),
		),
	)

	if conf.ServerTokens {
		w.Header().Set("Server", fmt.Sprintf("eldim %s", version))
	}

	/* Start Request Service Timer */
	now := time.Now().Unix()

	/* Get IP Address of Request */
	ipAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Error("failed to parse remote IP of request", "remote_addr", r.RemoteAddr, "error", err)
	}

	/* Limit request body size */
	r.Body = http.MaxBytesReader(w, r.Body, conf.MaxUploadSize*1024*1024)

	/* Begin file processing */
	log.Info("parsing upload")
	err = r.ParseMultipartForm(conf.MaxUploadRAM * 1024 * 1024)
	if err != nil {
		if err.Error() == "http: request body too large" {
			log.Error("upload exceeds maximum size", "max_mb", conf.MaxUploadSize)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			fmt.Fprintf(w, "Upload exceeds maximum allowed size")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "413"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "Upload-Too-Large"}).Inc()
			return
		}
		if err == io.EOF {
			log.Error("upload cancelled")
		} else {
			log.Error("unable to parse multipart form", "error", err)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error while processing upload request")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Multipart-Form-Parse-Error"}).Inc()
		return
	}
	defer r.MultipartForm.RemoveAll()
	log.Info("upload parsed")

	/* Check if the Password supplied is allowed and matches a host */
	hostname, err := getPassName(r.PostFormValue("password"))
	if err != nil {
		/*
			This is the case in which the password that was supplied by
			the user did not match any of the passwords in the database.

			This means we need to do an IP-based check, and try and see
			if this IP Address is allowed as a client.
		*/
		log.Info("password did not match, checking by IP")

		hostname, err = getIPName(ipAddr)
		if err != nil {
			log.Warn("authentication failed", "error", err)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusForbidden)
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
	log.Info("client authenticated", "hostname", hostname)
	promHostAuths.With(p.Labels{"hostname": hostname}).Inc()

	/* Check if a file name has been provided */
	if r.PostFormValue("filename") == "" {
		log.Error("file name not provided", "hostname", hostname)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "File name not supplied")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Name-Not-Provided"}).Inc()
		return
	}

	/* Validate the file name */
	if !isValidFilename(r.PostFormValue("filename")) {
		log.Error("invalid file name supplied", "hostname", hostname, "filename", r.PostFormValue("filename"))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid file name")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Name-Invalid"}).Inc()
		return
	}

	/* All files are <hostname>/<desired_name> */
	uploadFileName := fmt.Sprintf("%s/%s", hostname, r.PostFormValue("filename"))

	/* Check if this file is already being processed by this instance */
	if _, loaded := currentUploads.LoadOrStore(uploadFileName, true); loaded {
		log.Error("file already being uploaded by another request", "file", uploadFileName)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "File is already being uploaded.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "409"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Name-Uploaded-In-Parallel-Map"}).Inc()
		return
	}
	defer currentUploads.Delete(uploadFileName)

	/* Connect to all Backends */
	log.Info("connecting to backends", "file", uploadFileName)
	var backends []backend.Client
	for _, be := range conf.Clients() {
		log.Info("connecting to backend",
			slog.Group("backend", "name", be.Name(), "type", be.BackendName()),
		)

		err := be.Connect(r.Context())
		if err != nil {
			log.Error("backend connection failed",
				slog.Group("backend", "name", be.Name(), "type", be.BackendName()),
				"error", err,
			)
			promFileUpErrors.With(p.Labels{
				"error": fmt.Sprintf(
					"%s-Backend-Connection-Error",
					strings.ReplaceAll(be.BackendName(), " ", "-"),
				),
			}).Inc()
			continue
		}
		log.Info("backend connected",
			slog.Group("backend", "name", be.Name(), "type", be.BackendName()),
		)

		/* Disconnect from the backend regardless of request status */
		defer be.Disconnect(context.Background())

		backends = append(backends, be)
	}

	if len(backends) == 0 {
		log.Error("no backends available to handle requests")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "An error occured while processing the uploaded file")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "No-Backends-Available"}).Inc()
		return
	}
	log.Info("backends ready", "live", len(backends))

	/* Check if file exists in all available containers */
	log.Info("checking if file exists in any backend", "file", uploadFileName)
	for _, be := range backends {
		exists, err := be.ObjectExists(r.Context(), fmt.Sprintf("%s/%s", hostname, r.PostFormValue("filename")))
		if err != nil {
			log.Error("failed to check if object exists",
				slog.Group("backend", "name", be.Name()),
				"file", uploadFileName,
				"error", err,
			)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "An error occured while processing the uploaded file")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "Error-Check-If-Object-Exists-In-Backend"}).Inc()
			return
		}
		if exists {
			log.Error("file already exists",
				slog.Group("backend", "name", be.Name()),
				"file", uploadFileName,
			)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "File already exists.")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "File-Already-Exists"}).Inc()
			return
		}
	}
	log.Info("file does not exist in any backend", "file", uploadFileName)

	/* Process uploaded file */
	file, _, err := r.FormFile("file")
	if err != nil {
		log.Error("uploaded file error", "file", uploadFileName, "error", err)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
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
	uploadSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		log.Error("failed to seek to end of file", "file", uploadFileName, "error", err)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "An error occurred while processing the uploaded file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Seek-To-End-Failed"}).Inc()
		return
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		log.Error("failed to seek to start of file", "file", uploadFileName, "error", err)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "An error occurred while processing the uploaded file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Seek-To-Start-Failed"}).Inc()
		return
	}

	log.Info("file received", "file", uploadFileName, "plaintext_bytes", uploadSize)
	promBytesUploadedSuc.Add(float64(uploadSize))
	log.Info("encrypting file", "file", uploadFileName)

	/* Load all Recipients from configuration */
	var rcpt []age.Recipient
	for _, r := range conf.Encryption.AgeID {
		ar, err := age.ParseX25519Recipient(r)
		if err != nil {
			log.Error("failed to parse age ID recipient", "error", err)
			continue
		}
		rcpt = append(rcpt, age.Recipient(ar))
	}
	for _, r := range conf.Encryption.AgeSSH {
		ar, err := agessh.ParseRecipient(r)
		if err != nil {
			log.Error("failed to parse age SSH recipient", "error", err)
			continue
		}
		rcpt = append(rcpt, age.Recipient(ar))
	}

	if len(rcpt) == 0 {
		log.Error("no valid encryption recipients found",
			"age_id_configured", len(conf.Encryption.AgeID),
			"age_ssh_configured", len(conf.Encryption.AgeSSH),
		)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "No-Valid-Age-Recipients-Found"}).Inc()
		return
	}

	/* Initialize age for encryption */
	encBuff := &bytes.Buffer{}

	ew, err := age.Encrypt(encBuff, rcpt...)
	if err != nil {
		log.Error("failed to initialize encryption", "file", uploadFileName, "recipients", len(rcpt), "error", err)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Initialize-Age-Encryption"}).Inc()
		return
	}

	/* Encrypt file */
	wb, err := io.Copy(ew, file)
	if err != nil || wb != uploadSize {
		log.Error("encryption failed",
			"file", uploadFileName,
			"expected_bytes", uploadSize,
			"written_bytes", wb,
			"error", err,
		)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Encrypt-File"}).Inc()
		return
	}

	if err := ew.Close(); err != nil {
		log.Error("encryption close failed", "file", uploadFileName, "error", err)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Encrypt-File-Close"}).Inc()
		return
	}

	encrSize := int64(encBuff.Len())

	log.Info("encryption completed",
		"file", uploadFileName,
		slog.Group("encryption",
			"plaintext_bytes", uploadSize,
			"ciphertext_bytes", encrSize,
			"recipients", len(rcpt),
		),
	)

	/* Counts successful uploads */
	uploads := 0

	/* For every backend */
	for _, be := range backends {
		log.Info("uploading to backend",
			"file", uploadFileName,
			slog.Group("backend", "name", be.Name(), "type", be.BackendName()),
			"ciphertext_bytes", encrSize,
		)

		beStart := time.Now().Unix()
		err := be.UploadFile(context.Background(), uploadFileName, bytes.NewReader(encBuff.Bytes()), encrSize)
		beDurationSec := time.Now().Unix() - beStart

		if err != nil {
			log.Error("backend upload failed",
				"file", uploadFileName,
				slog.Group("backend", "name", be.Name(), "type", be.BackendName()),
				"duration_s", beDurationSec,
				"error", err,
			)
			promFileUpErrors.With(p.Labels{
				"error": fmt.Sprintf(
					"%s-Upload-Failed", strings.ReplaceAll(be.BackendName(), " ", "-"),
				),
			}).Inc()
		} else {
			uploads++
			log.Info("backend upload succeeded",
				"file", uploadFileName,
				slog.Group("backend", "name", be.Name(), "type", be.BackendName()),
				"duration_s", beDurationSec,
			)
			promBytesUploaded.With(
				p.Labels{"backendtype": strings.ReplaceAll(be.BackendName(), " ", "-")},
			).Add(float64(encrSize))
		}
	}

	/* Reset the file buffer */
	encBuff.Reset()

	/* Check if at least one file was uploaded */
	if uploads == 0 {
		log.Error("all backend uploads failed", "file", uploadFileName)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to store file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "All-Uploads-Failed"}).Inc()
		return
	}

	/* All good, finally it's over */
	durationSec := time.Now().Unix() - now
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Ok")

	/* Update Prometheus on the successful request handling */
	promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "200"}).Inc()
	promReqServTimeHist.Observe(float64(durationSec))
	promHostUploads.With(p.Labels{"hostname": hostname}).Inc()

	log.Info("upload completed",
		"file", uploadFileName,
		"hostname", hostname,
		slog.Group("upload",
			"backends_succeeded", uploads,
			"backends_total", len(backends),
			"plaintext_bytes", uploadSize,
			"ciphertext_bytes", encrSize,
			"duration_s", durationSec,
		),
		"status", 200,
	)
}
