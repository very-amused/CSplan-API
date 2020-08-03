package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/very-amused/CSplan-API/routes"
)

type HTTPHeaders map[string]string

const port = 3000
const badDataErr = "Data retrieved is not equal to data expected"

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
	list routes.TodoList = routes.TodoList{
		Title: encode("Sample Todo List"),
		Items: []routes.TodoItem{
			routes.TodoItem{
				Title:       encode("Item 1"),
				Description: encode("Sample Description")}},
		Meta: routes.IndexedMeta{
			CryptoKey: encode("EncryptedKey")}}
	listPatch routes.TodoPatch = routes.TodoPatch{
		Title: encode("new title")}
)

func DoRequest(
	method string,
	url string,
	body interface{},
	headers HTTPHeaders,
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
		// Format an error based on status if no response message is given
		if len(httpErr.Message) == 0 {
			httpErr.Status = r.StatusCode
			httpErr.Message = fmt.Sprintf("Expected status %d, received status %d", expectedStatus, httpErr.Status)
		}
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
		log.Fatalf("Failed to create test account: %s", err)
	}

	// Login to test account
	r, err = DoRequest("POST", route("/login"), user, nil, 200)
	if err != nil {
		log.Fatalf("Failed to login to test account: %s", err)
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
		log.Fatalf("Failed to delete test account: %s", err)
	}
	// Repeat the request with confirmation token
	var dt routes.DeleteToken
	json.NewDecoder(r.Body).Decode(&dt)
	r, err = DoRequest("DELETE", route("/account/delete"), nil, HTTPHeaders{
		"X-Confirm": dt.Token}, 200)

	os.Exit(exit)
}

func TestName(t *testing.T) {
	var rBody routes.Name
	t.Run("Create Name", func(t *testing.T) {
		r, err := DoRequest("POST", route("/name"), name, nil, 201)
		if err != nil {
			t.Fatal(err)
		}
		// Update meta
		json.NewDecoder(r.Body).Decode(&rBody)
		name.Meta.Checksum = rBody.Meta.Checksum
	})
	t.Run("Get Name", func(t *testing.T) {
		r, err := DoRequest("GET", route("/name"), nil, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, name) {
			t.Error(badDataErr)
		}
	})
	t.Run("Update Name", func(t *testing.T) {
		_, err := DoRequest("PATCH", route("/name"), namePatch, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		name.Username = namePatch.Username
	})
	t.Run("Updates Correctly Applied", func(t *testing.T) {
		r, err := DoRequest("GET", route("/name"), nil, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if rBody.Username != name.Username {
			t.Errorf("Retrieved username '%s' from /name, expected '%s'", rBody.Username, name.Username)
		}
	})
	t.Run("Delete Name", func(t *testing.T) {
		_, err := DoRequest("DELETE", route("/name"), nil, nil, 204)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestTodo(t *testing.T) {
	var rBody routes.TodoList
	t.Run("Create Todo List", func(t *testing.T) {
		r, err := DoRequest("POST", route("/todos"), list, nil, 201)
		if err != nil {
			t.Fatal(err)
		}
		// Update ID + checksum
		json.NewDecoder(r.Body).Decode(&rBody)
		list.Meta.Checksum = rBody.Meta.Checksum
		list.EncodedID = rBody.EncodedID
	})
	t.Run("Get Todo List", func(t *testing.T) {
		r, err := DoRequest("GET", route("/todos/"+list.EncodedID), nil, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, list) {
			t.Error(badDataErr)
		}
	})
	t.Run("Update Todo List", func(t *testing.T) {
		_, err := DoRequest("PATCH", route("/todos/"+list.EncodedID), listPatch, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		list.Title = listPatch.Title
	})
	t.Run("Updates Correctly Applied", func(t *testing.T) {
		r, err := DoRequest("GET", route("/todos/"+list.EncodedID), nil, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if rBody.Title != list.Title {
			t.Errorf("Retrieved title '%s' from /todos/%s, expected '%s'", rBody.Title, list.EncodedID, list.Title)
		}
	})
	t.Run("Delete Todo List", func(t *testing.T) {
		_, err := DoRequest("DELETE", route("/todos/"+list.EncodedID), nil, nil, 204)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestPreflight(t *testing.T) {
	// Expect to succeed options requests for auth level 0 routes with the correct requested method
	t.Run("Auth Level 0", func(t *testing.T) {
		_, err := DoRequest("OPTIONS", route("/register"), nil, HTTPHeaders{
			"Access-Control-Request-Method": "POST"}, 200)
		if err != nil {
			t.Error(err)
		}
		_, err = DoRequest("OPTIONS", route("/login"), nil, HTTPHeaders{
			"Access-Control-Request-Method": "POST"}, 200)
		if err != nil {
			t.Error(err)
		}
	})
	// If no method if specified in the preflight headers,
	// the API must return a 200 response if the user is authorized for the route
	t.Run("No Method Specified", func(t *testing.T) {
		_, err := DoRequest("OPTIONS", route("/register"), nil, nil, 200)
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("Bad Method", func(t *testing.T) {
		_, err := DoRequest("OPTIONS", route("/register"), nil, HTTPHeaders{
			"Access-Control-Request-Method": "PUT"}, 405)
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("Auth Level 1", func(t *testing.T) {
		_, err := DoRequest("OPTIONS", route("/todos"), nil, HTTPHeaders{
			"Access-Control-Request-Method": "GET"}, 200)
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("Incorrect Creds", func(t *testing.T) {
		_, err := DoRequest("OPTIONS", route("/todos"), nil, HTTPHeaders{
			"Access-Control-Request-Method": "GET",
			"CSRF-Token":                    "INVALID_TOKEN"}, 401)
		if err != nil {
			t.Error(err)
		}
	})
}
