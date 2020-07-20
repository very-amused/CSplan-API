package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/very-amused/CSplan-API/routes"
)

type HTTPHeaders map[string]string

const port = 3000

// Helper function for managing base64 encoding
func encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

var (
	client *http.Client
	auth   routes.Tokens
	user   routes.User = routes.User{
		Email:    "user@test.com",
		Password: "TestPassword"}
	name routes.Name = routes.Name{
		FirstName: encode("John"),
		LastName:  encode("Doe"),
		Username:  encode("JDoe"),
		Meta: routes.Meta{
			CryptoKey: encode("EncryptedKey")}}
	namePatch routes.NamePatch = routes.NamePatch{
		Username: encode("JDoe2")}
)

func DoRequest(
	method string,
	url string,
	body interface{},
	headers map[string]string,
	expectedStatus int) (r *http.Response, e error) {
	var buffer bytes.Buffer
	// Encode body into buffer
	if body != nil {
		marshalled, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buffer.Write(marshalled)
	}

	// Create request
	req, err := http.NewRequest(method, url, &buffer)
	if err != nil {
		return nil, err
	}

	// Add appropriate headers (content type, authentication, any additional headers specified)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if len(auth.Token) > 0 && len(auth.CSRFtoken) > 0 {
		var cookie strings.Builder
		cookie.WriteString("Authorization=")
		cookie.WriteString(auth.Token)
		req.Header.Set("Cookie", cookie.String())
		req.Header.Set("CSRF-Token", auth.CSRFtoken)
	}
	for header, value := range headers {
		req.Header.Set(header, value)
	}

	// Do the request
	r, e = client.Do(req)
	if e == nil && r.StatusCode != expectedStatus {
		var httpErr routes.Error
		json.NewDecoder(r.Body).Decode(&httpErr)
		e = httpErr
	}
	return r, e
}

func route(path string) string {
	return fmt.Sprintf("http://localhost:%d%s", port, path)
}

func TestMain(m *testing.M) {
	// Initialize http client
	client = &http.Client{}
	// Create test account
	r, err := DoRequest("POST", route("/register"), user, nil, 201)
	if err != nil {
		log.Fatalf("Failed to create test account: %s", err.Error())
	}

	// Login to test account
	r, err = DoRequest("POST", route("/login"), user, nil, 200)
	if err != nil {
		log.Fatalf("Failed to login to test account: %s", err.Error())
	}
	// Store auth tokens
	cookieHeader := r.Header.Get("Set-Cookie")
	cookie := strings.Split(cookieHeader, ";")[0]
	auth.Token = strings.Split(cookie, "=")[1]
	json.NewDecoder(r.Body).Decode(&auth)

	// Run tests
	exit := m.Run()

	// Delete test account
	r, err = DoRequest("DELETE", route("/account/delete"), nil, nil, 200)
	if err != nil {
		log.Fatalf("Failed to delete test account: %s", err.Error())
	}
	// Repeat the request with confirmation token
	var dt routes.DeleteToken
	json.NewDecoder(r.Body).Decode(&dt)
	r, err = DoRequest("DELETE", route("/account/delete"), nil, HTTPHeaders{
		"X-Confirm": dt.Token}, 200)

	os.Exit(exit)
}

func TestName(t *testing.T) {
	t.Run("Create Name", func(t *testing.T) {
		_, err := DoRequest("POST", route("/name"), name, nil, 201)
		if err != nil {
			t.Fatal(err.Error())
		}
	})
	t.Run("Get Name", func(t *testing.T) {
		_, err := DoRequest("GET", route("/name"), nil, nil, 200)
		if err != nil {
			t.Fatal(err.Error())
		}
	})
	t.Run("Update Name", func(t *testing.T) {
		_, err := DoRequest("PATCH", route("/name"), namePatch, nil, 200)
		if err != nil {
			t.Fatal(err.Error())
		}
	})
	t.Run("Delete Name", func(t *testing.T) {
		_, err := DoRequest("DELETE", route("/name"), nil, nil, 204)
		if err != nil {
			t.Fatal(err.Error())
		}
	})
}
