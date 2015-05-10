/*
 Copyright (C) 2015 Patrick Griffis <tingping@tingping.se>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/blowfish"
)

// http://6xq.net/playground/pandora-apidoc/json/errorcodes/
const (
	INTERNAL_ERROR               = 0
	URL_PARAM_MISSING_METHOD     = 2
	URL_PARAM_MISSING_PARTNER_ID = 4
	SECURE_PROTOCOL_REQUIRED     = 6
	API_VERSION_NOT_SUPPORTED    = 11
	INSUFFICIENT_CONNECTIVITY    = 13 /* Synctime? */
	UNKNOWN_METHOD_NAME          = 14
	INVALID_PARTNER_LOGIN        = 1002
	INVALID_USERNAME             = 1011
	INVALID_PASSWORD             = 1012
)

type Partner struct {
	Username    string
	Password    string
	DeviceModel string
	EncryptKey  string
	DecryptKey  string
}

var Partners = loadPartners()

func loadPartners() map[string]Partner {
	file, err := ioutil.ReadFile("./partners.json")
	if err != nil {
		log.Fatalln(err)
	}

	var output map[string]Partner
	err = json.Unmarshal(file, &output)
	if err != nil {
		log.Fatalln(err)
	}
	return output
}

type Account struct {
	Password string
}

var Accounts = loadAccounts()

func loadAccounts() map[string]Account {
	file, err := ioutil.ReadFile("./accounts.json")
	if err != nil {
		log.Fatalln(err)
	}

	output := make(map[string]Account)
	err = json.Unmarshal(file, &output)
	if err != nil {
		log.Fatalln(err)
	}
	return output
}

func newApiError(message string, code uint16) string {
	return fmt.Sprintf(`{"stat":"fail","message":"%s","code":%d}`, message, code)
}

// From gopiano
func encrypt(data string, key string) (string, error) {
	chunks := make([]string, 0)
	encrypter, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	for i := 0; i < len(data); i += 8 {
		var buf [8]byte
		var crypt [8]byte
		copy(buf[:], data[i:])
		encrypter.Encrypt(crypt[:], buf[:])
		encoded := hex.EncodeToString(crypt[:])
		chunks = append(chunks, encoded)
	}

	return strings.Join(chunks, ""), nil
}

func decrypt(data string, key string) (string, error) {
	chunks := make([]string, 0)
	decrypter, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	for i := 0; i < len(data); i += 16 {
		var buf [16]byte
		var decoded, decrypted [8]byte
		copy(buf[:], data[i:])
		_, err := hex.Decode(decoded[:], buf[:])
		if err != nil {
			return "", err
		}
		decrypter.Decrypt(decrypted[:], decoded[:])
		chunks = append(chunks, strings.Trim(string(decrypted[:]), "\x00"))
	}

	return strings.Join(chunks, ""), nil
}

func makeSyncTime(key string) string {
	now := time.Now().Unix()

	rand, err := rand.Int(rand.Reader, big.NewInt(9999))
	if err != nil {
		panic(err)
	}
	enc_now, err := encrypt(fmt.Sprintf("%d%d", rand, now), key)
	if err != nil {
		panic(err) // TODO
	}

	return enc_now
}

// http://6xq.net/playground/pandora-apidoc/json/authentication/#partner-login
func handlePartnerLogin(body []byte) string {
	var info map[string]interface{}
	err := json.Unmarshal(body, &info)
	if err != nil {
		log.Println(err)
		return newApiError("Invalid body", INTERNAL_ERROR)
	}

	version := info["version"]
	if version != "5" {
		return newApiError("Version not supported!", API_VERSION_NOT_SUPPORTED)
	}

	username := info["username"]
	password := info["password"]
	for id, partner := range Partners {
		if partner.Username == username && partner.Password == password {
			return fmt.Sprintf(`{"stat":"ok","result":{"syncTime":"%s","partnerAuthToken":"%s","partnerId":"%s"}}`,
				makeSyncTime(partner.EncryptKey), "TODO", id)
		}
	}

	return newApiError("Partner info not found", INVALID_PARTNER_LOGIN)
}

func handleUserLogin(body []byte, partnerId string) string {
	unencrypted_body, err := decrypt(string(body), Partners[partnerId].DecryptKey)
	if err != nil {
		log.Println(err)
		return newApiError("Invalid body", INTERNAL_ERROR)
	}

	fmt.Println(string(unencrypted_body))
	var info map[string]interface{}
	err = json.Unmarshal([]byte(unencrypted_body), &info)
	if err != nil {
		log.Println(err)
		return newApiError("Invalid body", INTERNAL_ERROR)
	}

	logintype := info["loginType"]
	if logintype != "user" {
		return newApiError("Unknown login type", INTERNAL_ERROR)
	}

	/*synctime := info["syncTime"]
	if (synctime != ) {
		return newApiError("Bad synctime", INSUFFICIENT_CONNECTIVITY)
	}*/

	email, ok := info["username"].(string)
	if ok != true {
		return newApiError("Invalid email", INVALID_USERNAME)
	}

	account, ok := Accounts[email]
	if ok != true {
		// Yay leaking user information
		return newApiError("Invalid email", INVALID_USERNAME)
	}

	if account.Password != info["password"] {
		return newApiError("Invalid password", INVALID_PASSWORD)
	}

	return fmt.Sprintf(`{"stat":"ok","result":{"userId":"%s","userAuthToken":"%s"}}`,
		"TODO", "TODO")
}

func handleMain(w http.ResponseWriter, r *http.Request) {

	log.Println("Recived requesturi:", r.RequestURI)

	u, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		fmt.Fprintf(w, newApiError(fmt.Sprintf("Error parsing request uri; %v", err), INTERNAL_ERROR))
		return
	}

	method, ok := u.Query()["method"]
	if !ok {
		fmt.Fprintf(w, newApiError("No method in url", URL_PARAM_MISSING_METHOD))
		return
	}

	body := make([]byte, 1024) // Better size?
	n, err := r.Body.Read(body)
	r.Body.Close()
	if err != nil && err != io.EOF {
		fmt.Fprintf(w, newApiError(fmt.Sprintf("Failed to read body: %v", err), INTERNAL_ERROR))
		return
	}

	log.Println("Recived body:", string(body))
	switch method[0] {
	case "auth.partnerLogin":
		if r.TLS == nil {
			fmt.Fprintf(w, newApiError("TLS required", SECURE_PROTOCOL_REQUIRED))
		} else {
			fmt.Fprintf(w, handlePartnerLogin(body[:n]))
		}
	case "auth.userLogin":
		partnerId, ok := u.Query()["partner_id"]
		if ok != true || len(partnerId) != 1 {
			fmt.Fprintf(w, newApiError("Missing partner id", URL_PARAM_MISSING_PARTNER_ID))
		} else if r.TLS == nil {
			fmt.Fprintf(w, newApiError("TLS required", SECURE_PROTOCOL_REQUIRED))
		} else {
			fmt.Fprintf(w, handleUserLogin(body[:n], partnerId[0]))
		}
	default:
		fmt.Fprintf(w, newApiError("Uknown method", UNKNOWN_METHOD_NAME))
	}
}

func startServers() chan error {
	errs := make(chan error)

	go func() {
		if err := http.ListenAndServe(":80", nil); err != nil {
			errs <- err
		}
	}()

	go func() {
		if err := http.ListenAndServeTLS(":443", "./server.crt", "./server.key", nil); err != nil {
			errs <- err
		}
	}()

	// TODO: Drop privs after binding ports
	log.Printf("Listening...")
	return errs
}

func main() {
	http.HandleFunc("/", handleMain)

	errs := startServers()

	select {
	case err := <-errs:
		log.Fatalln("Could not start service:", err)
	}
}
