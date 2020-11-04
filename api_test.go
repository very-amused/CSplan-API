package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"

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
	user   = routes.User{
		Email: "user@test.com"}
	password = []byte("correcthorsebatterystaple")

	keys = routes.CryptoKeys{
		PublicKey:  encode("public key"),
		PrivateKey: encode("private key"),
		PBKDF2salt: encode("secure salt")}

	name = routes.Name{
		FirstName: encode("John"),
		LastName:  encode("Doe"),
		Username:  encode("JDoe"),
		Meta: routes.Meta{
			CryptoKey: encode("EncryptedKey")}}
	namePatch = routes.NamePatch{
		Username: encode("JDoe2")}

	list = routes.TodoList{
		Title: encode("Sample Todo List"),
		Items: []routes.TodoItem{
			routes.TodoItem{
				Title:       encode("Item 1"),
				Description: encode("Sample Description"),
				Done:        encode("false"),
				Tags:        make([]string, 0)}},
		Meta: routes.IndexedMeta{
			CryptoKey: encode("EncryptedKey")}}
	listPatch = routes.TodoPatch{
		Title: encode("new title")}

	tag = routes.Tag{
		Name:  encode("Sample Tag"),
		Color: encode("#444"),
		Meta: routes.TagMeta{
			CryptoKey: encode("EncryptedKey")}}
	tagPatch = routes.TagPatch{
		Name: encode("New Name"),
		Meta: routes.TagMetaPatch{
			CryptoKey: encode("New Key")}}

	nolist = routes.NoList{
		Items: []routes.TodoItem{
			routes.TodoItem{
				Title:       encode("Nolist item"),
				Description: encode("Sample Description")}},
		Meta: routes.Meta{
			CryptoKey: encode("EncryptedKey")}}
	nolistItemPatch = []routes.TodoItem{
		routes.TodoItem{
			Title:       encode("New Item"),
			Description: encode("This one is new")}}
	nolistMetaPatch = routes.MetaPatch{
		CryptoKey: encode("New Key")}
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
			// Read raw response body
			body, _ := ioutil.ReadAll(r.Body)
			httpErr.Message = fmt.Sprintf("Expected status %d, received status %d\n%s", expectedStatus, httpErr.Status, string(body))
		}
		e = httpErr
	}
	return r, e
}

func route(path string) string {
	return fmt.Sprintf("https://localhost:%d%s", port, path)
}

func TestMain(m *testing.M) {
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
	if err != nil {
		log.Fatalf("Failed to delete test account: %s", err)
	}

	os.Exit(exit)
}

func TestKeys(t *testing.T) {
	var rBody routes.CryptoKeys
	t.Run("Create Keypair", func(t *testing.T) {
		_, err := DoRequest("POST", route("/keys"), keys, nil, 201)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Get Keypair", func(t *testing.T) {
		r, err := DoRequest("GET", route("/keys"), nil, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, keys) {
			t.Fatal(badDataErr)
		}
	})
	t.Run("Update Keypair", func(t *testing.T) {
		keys.PublicKey = encode("new public key")
		_, err := DoRequest("PATCH", route("/keys"), keys, nil, 204)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Updates Correctly Applied", func(t *testing.T) {
		r, err := DoRequest("GET", route("/keys"), nil, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, keys) {
			t.Fatal(badDataErr)
		}
	})
}

func TestChallengeAuth(t *testing.T) {
	var authKey []byte
	var challenge routes.Challenge
	var encoded string
	var ivAndEncryptedData []byte
	t.Run("PBKDF2", func(t *testing.T) {
		salt := make([]byte, 16)
		rand.Read(salt)
		authKey = pbkdf2.Key(password, salt, 200000, 32, sha512.New)
		encoded = base64.StdEncoding.EncodeToString(append(salt, authKey...))
	})
	t.Run("Update AuthKey", func(t *testing.T) {
		_, err := DoRequest("PATCH", route("/authkey"), routes.AuthKeyPatch{
			AuthKey: encoded}, nil, 204)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Request Auth Challenge", func(t *testing.T) {
		r, err := DoRequest("POST", route("/challenge?action=request"), user, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&challenge)
		ivAndEncryptedData, _ = base64.StdEncoding.DecodeString(challenge.EncodedData)
	})
	t.Run("Decrypt Challenge Data", func(t *testing.T) {
		// Recreate the key derivation using the params sent by the API
		salt, _ := base64.StdEncoding.DecodeString(challenge.Salt)
		iv := ivAndEncryptedData[0:12]
		newKey := pbkdf2.Key(password, salt, 200000, 32, sha512.New)

		// Decrypt the challenge data
		encryptedData := ivAndEncryptedData[12:]
		block, _ := aes.NewCipher(newKey)
		gcm, _ := cipher.NewGCM(block)
		decrypted, err := gcm.Open(nil, iv, encryptedData, nil)
		if err != nil {
			t.Fatal(err)
		}
		challenge.EncodedData = base64.StdEncoding.EncodeToString(decrypted)
	})
	t.Run("Submit Challenge", func(t *testing.T) {
		r, err := DoRequest("POST", route("/challenge/"+challenge.EncodedID+"?action=submit"), challenge, nil, 200)
		if err != nil {
			t.Fatal(err)
		}
		var tokens routes.Tokens
		json.NewDecoder(r.Body).Decode(&tokens)
	})
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

func TestTags(t *testing.T) {
	var rBody routes.Tag
	t.Run("Create Tag", func(t *testing.T) {
		r, err := DoRequest("POST", route("/tags"), tag, nil, 201)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		tag.Meta.Checksum = rBody.Meta.Checksum
		tag.EncodedID = rBody.EncodedID
	})
	t.Run("Get Tag", func(t *testing.T) {
		r, err := DoRequest("GET", route("/tags/"+tag.EncodedID), nil, nil, 200)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, tag) {
			t.Error(badDataErr)
		}
	})
	t.Run("Update Tag", func(t *testing.T) {
		r, err := DoRequest("PATCH", route("/tags/"+tag.EncodedID), tagPatch, nil, 200)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		tag.Name = tagPatch.Name
		tag.Meta.CryptoKey = tagPatch.Meta.CryptoKey
		tag.Meta.Checksum = rBody.Meta.Checksum
	})
	t.Run("Updates Correctly Applied", func(t *testing.T) {
		r, err := DoRequest("GET", route("/tags/"+tag.EncodedID), nil, nil, 200)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, tag) {
			t.Error(badDataErr)
		}
	})
	t.Run("Delete Tag", func(t *testing.T) {
		_, err := DoRequest("DELETE", route("/tags/"+tag.EncodedID), nil, nil, 204)
		if err != nil {
			t.Error(err)
		}
	})
}

func TestNoList(t *testing.T) {
	var rBody routes.NoList
	t.Run("Create NoList", func(t *testing.T) {
		r, err := DoRequest("POST", route("/nolist"), nolist, nil, 201)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		nolist.Meta.Checksum = rBody.Meta.Checksum
	})
	t.Run("Get NoList", func(t *testing.T) {
		r, err := DoRequest("GET", route("/nolist"), nil, nil, 200)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		if !reflect.DeepEqual(rBody, nolist) {
			t.Error(badDataErr)
		}
	})
	t.Run("Update Items", func(t *testing.T) {
		_, err := DoRequest("PATCH", route("/nolist"), routes.NoList{
			Items: nolistItemPatch}, nil, 200)
		if err != nil {
			t.Error(err)
		} else {
			nolist.Items = nolistItemPatch
		}
	})
	t.Run("Update CryptoKey", func(t *testing.T) {
		_, err := DoRequest("PATCH", route("/nolist"), routes.NoListPatch{
			Meta: nolistMetaPatch}, nil, 200)
		if err != nil {
			t.Error(err)
		} else {
			nolist.Meta.CryptoKey = nolistMetaPatch.CryptoKey
			nolist.Meta.Checksum = nolistMetaPatch.Checksum
		}
	})
	t.Run("Updates Correctly Applied", func(t *testing.T) {
		r, err := DoRequest("GET", route("/nolist"), nil, nil, 200)
		if err != nil {
			t.Error(err)
		}
		json.NewDecoder(r.Body).Decode(&rBody)
		nolist.Meta.Checksum = rBody.Meta.Checksum
		if !reflect.DeepEqual(rBody, nolist) {
			t.Error(badDataErr)
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
	// If a method is specified in the preflight headers
	// the API must return a 405 response if the method is invalid for the route
	t.Run("Bad Method", func(t *testing.T) {
		_, err := DoRequest("OPTIONS", route("/register"), nil, HTTPHeaders{
			"Access-Control-Request-Method": "PUT"}, 405)
		if err != nil {
			t.Error(err)
		}
	})
}
