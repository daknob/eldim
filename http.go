package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/daknob/hlog"
	p "github.com/prometheus/client_golang/prometheus"

	"github.com/keybase/go-triplesec"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/ncw/swift"
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
		logrus.Errorf("%s: Failed to parse Remote IP of request: %v", rid, err)
	}

	/* Check if the Password supplied is allowed and matches a host */
	hostname, err := getPassName(r.PostFormValue("password"))
	if err != nil {
		/*
			This is the case in which the password that was supplied by
			the user did not match any of the passwords in the database.

			This means we need to do an IP-based check, and try and see
			if this IP Address is allowed as a client.
		*/
		logrus.Printf("%s: Client at %s did not supply a known password. Checking by IP", rid, ipAddr)

		hostname, err = getIPName(ipAddr)
		if err != nil {
			logrus.Printf("%s: IP Address %s is not a known client", rid, ipAddr)
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
	logrus.Printf("%s: Detected Hostname: %s", rid, hostname)
	promHostAuths.With(p.Labels{"hostname": hostname}).Inc()

	/* Begin file processing */
	logrus.Printf("%s: Parsing upload from %s [%s]", rid, hostname, ipAddr)
	err = r.ParseMultipartForm(conf.MaxUploadRAM * 1024 * 1024)
	if err != nil {
		if err == io.EOF {
			logrus.Errorf("%s: Upload cancelled", rid)
		} else {
			logrus.Errorf("%s: Unable to parse multipart form: %v", rid, err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Error while processing upload request")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Multipart-Form-Parse-Error"}).Inc()
		return
	}
	logrus.Printf("%s: Done parsing upload", rid)

	/* Check if a file name has been provided */
	if r.PostFormValue("filename") == "" {
		logrus.Errorf("%s: Did not provide a file name to save the file as", rid)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "File name not supplied")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Name-Not-Provided"}).Inc()
		return
	}

	/* Connect to all Swift Backends */
	logrus.Printf("%s: Connecting to OpenStack Swift Backends...", rid)
	var sc []*swift.Connection
	var co []string
	var na []string
	var ex []int
	for _, be := range conf.SwiftBackends {
		logrus.Printf("%s: Connecting to \"%s\"", rid, be.Name)

		c := swift.Connection{
			UserName:     be.Username,
			ApiKey:       be.Apikey,
			AuthUrl:      be.AuthURL,
			Domain:       "default",
			Region:       be.Region,
			AuthVersion:  3,
			EndpointType: swift.EndpointTypePublic,
		}

		err := c.Authenticate()
		if err != nil {
			logrus.Errorf("%s: Unable to connect to OpenStack Swift Backend \"%s\"", rid, be.Name)
			promFileUpErrors.With(p.Labels{"error": "OpenStack-Swift-Backend-Connection-Error"}).Inc()
			continue
		}

		logrus.Printf("%s: Successfully authenticated with OpenStack Swift Backend \"%s\"", rid, be.Name)
		sc = append(sc, &c)
		co = append(co, be.Container)
		na = append(na, be.Name)
		ex = append(ex, be.ExpireSeconds)
	}
	if len(sc) == 0 {
		logrus.Errorf("%s: No OpenStack Swift Backend available to handle requests", rid)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "An error occured while processing the uploaded file")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "No-Openstack-Swift-Backends-Available"}).Inc()
		return
	}
	logrus.Printf("%s: Connection successful. %d OpenStack Swift Backends live.", rid, len(sc))

	/* Check if file exists in all available containers */
	logrus.Printf("%s: Checking if file exists already in any OpenStack Swift Backend...", rid)
	for i, sConn := range sc {
		_, _, err := sConn.Object(co[i], fmt.Sprintf("%s/%s", hostname, r.PostFormValue("filename")))
		if err != swift.ObjectNotFound {
			logrus.Errorf("%s: File \"%s\" already exists", rid, r.PostFormValue("filename"))
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "File already exists.")
			promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
			promFileUpErrors.With(p.Labels{"error": "File-Already-Exists"}).Inc()
			return
		}
	}
	logrus.Printf("%s: File does not exist in any OpenStack Swift Backend.", rid)

	/* Save uploaded file to disk */
	logrus.Printf("%s: Saving uploaded file to disk...", rid)

	newFilePath := fmt.Sprintf("%s/%s.dat", conf.TempUploadPath, uuid.New().String())

	file, _, err := r.FormFile("file")
	if err != nil {
		logrus.Errorf("%s: Uploaded File Error: %v", rid, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Did not supply a valid file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "400"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Invalid-Or-Missing"}).Inc()
		return
	}

	nfile, err := os.OpenFile(
		newFilePath,
		os.O_RDWR|os.O_CREATE,
		0600,
	)
	if err != nil {
		logrus.Errorf("%s: Failed to create local file for upload: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to save file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Creation-Failed"}).Inc()
		return
	}

	_, err = io.Copy(nfile, file)
	if err != nil {
		logrus.Errorf("%s: Failed to copy uploaded file to disk: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to save file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Copy-Failed"}).Inc()
		return
	}

	err = file.Close()
	if err != nil {
		logrus.Errorf("%s: Failed to close open file: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to save file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Close-Failed-IO-Error-Old"}).Inc()
		return
	}
	err = nfile.Close()
	if err != nil {
		logrus.Errorf("%s: Failed to close open file: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to save file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Close-Failed-IO-Error-New"}).Inc()
		return
	}

	logrus.Printf("%s: File successfully uploaded to %s", rid, newFilePath)
	logrus.Printf("%s: Loading file into RAM to encrypt and upload...", rid)

	/* Read file to RAM (byte array) so it can be used with TripleSec and Swift */
	upFile, err := ioutil.ReadFile(newFilePath)
	if err != nil {
		logrus.Errorf("%s: Failed to load file into RAM: %v", rid, err)
		os.Remove(newFilePath)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to save file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Read-Failed"}).Inc()
		return
	}

	err = os.Remove(newFilePath)
	if err != nil {
		logrus.Errorf("%s: Failed to delete temporary file at \"%s\": %v", rid, newFilePath, err)
		os.Remove(newFilePath)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to save file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "File-Delete-Failed"}).Inc()
		return
	}

	logrus.Printf("%s: File loaded into RAM. Size: %d bytes.", rid, len(upFile))
	promBytesUploadedSuc.Add(float64(len(upFile)))
	logrus.Printf("%s: Encrypting file...", rid)

	/*
	   Create a new TripleSec Cipher, with a nil salt (required)

	   The number 4 being passed is the Cipher version, with 4 being
	   currently the latest version according to the documentation.
	*/
	enc, err := triplesec.NewCipher([]byte(conf.EncryptionKey), nil, 4)
	if err != nil {
		logrus.Errorf("%s: Failed to initialize the encryption algorithm: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Initialize-TripleSec"}).Inc()
		return
	}

	/* Encrypt the file: takes a byte array, returns a byte array, 2*sizeof(file) in RAM */
	encFile, err := enc.Encrypt(upFile)
	if err != nil {
		logrus.Errorf("%s: Failed to encrypt the file: %v", rid, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to encrypt file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "Failed-To-Encrypt-File-TripleSec"}).Inc()
		return
	}

	upFile = []byte{}

	logrus.Printf("%s: Encryption completed", rid)
	logrus.Printf("%s: Uploading encrypted file to all OpenStack Swift Backends...", rid)

	/* All files are <hostname>/<desired_name> */
	uploadFileName := fmt.Sprintf("%s/%s", hostname, r.PostFormValue("filename"))
	/* Counts successful uploads */
	uploads := 0

	/* For every os swift backend */
	for i, be := range sc {
		logrus.Printf("%s: Uploading %s to %s", rid, uploadFileName, na[i])

		/* Upload actual file */
		err := be.ObjectPutBytes(co[i], uploadFileName, encFile, "application/octet-stream")
		if err != nil {
			logrus.Errorf("%s: Failed to upload %s to %s: %v", rid, uploadFileName, na[i], err)
			promFileUpErrors.With(p.Labels{"error": "OpenStack-Swift-Upload-Failed"}).Inc()
		} else {
			uploads++
			promBytesUploadedOSS.Add(float64(len(encFile)))
		}

		/* Set the expiry header */
		if ex[i] != 0 {
			err := be.ObjectUpdate(co[i], uploadFileName, map[string]string{
				"X-Delete-After": fmt.Sprintf("%d", ex[i]),
			})
			if err != nil {
				logrus.Errorf("%s: Failed to set expiry for file %s to %d seconds", rid, uploadFileName, ex[i])
				promFileUpErrors.With(p.Labels{"error": "OpenStack-Swift-Expiry-Set-Failed"}).Inc()
			}
		}

		/* Unauthenticate just to be sure */
		be.UnAuthenticate()
	}

	/* Check if at least one file was uploaded */
	if uploads == 0 {
		logrus.Errorf("%s: Did not manage to upload to any OpenStack Swift Backends!", rid)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Failed to store file.")
		promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "500"}).Inc()
		promFileUpErrors.With(p.Labels{"error": "OpenStack-Swift-All-Uploads-Failed"}).Inc()
	}

	/* All good, finally it's over */
	logrus.Printf("%s: Uploaded encrypted file to %d OpenStack Swift Backends", rid, uploads)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Ok")

	/* Update Prometheus on the successful request handling */
	promReqServed.With(p.Labels{"method": "POST", "path": "/api/v1/file/upload/", "status": "200"}).Inc()
	promReqServTimeHist.Observe(float64(time.Now().Unix() - now))
	promHostUploads.With(p.Labels{"hostname": hostname}).Inc()

}
