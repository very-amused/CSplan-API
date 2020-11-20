package routes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Challenge - Encryption challenge to obtain authentication
type Challenge struct {
	ID          uint   `json:"-"`
	EncodedID   string `json:"id"`
	Data        []byte `json:"-"`
	EncodedData string `json:"data"`
	Salt        string `json:"salt"`
}

func (challenge *Challenge) encryptData(block cipher.Block) error {
	// Generate an IV for the operation
	iv := make([]byte, 12)
	rand.Read(iv)

	// Create a GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	// Encrypt the data and store it as challenge.EncodedData
	encrypted := gcm.Seal(nil, iv, challenge.Data, nil)
	challenge.EncodedData = base64.StdEncoding.EncodeToString(append(iv, encrypted...))
	return nil
}

// RequestChallenge - Request an authentication challenge
func RequestChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Enforce action verbage
	if r.URL.Query().Get("action") != "request" {
		HTTPError(w, Error{
			Title:   "Invalid Action Parameter",
			Message: "To enforce semantics, all new challenge requests must contain '?action=request'.",
			Status:  422})
		return
	}

	var user User
	json.NewDecoder(r.Body).Decode(&user)

	if !user.exists() {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The user associated with the requested challenge does not exist.",
			Status:  404})
		return
	}
	// Get the user's ID
	DB.Get(&user.ID, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	// If there are 5 or more pending challenges for the user, decline providing a new one
	var count int
	DB.Get(&count, "SELECT COUNT(ID) FROM Challenges WHERE ID = ? AND Failed = 0")
	if count > 5 {
		HTTPError(w, Error{
			Title:   "Too Many Requests",
			Message: "There are too many pending challenges requested to provide a new one. You are being ratelimited.",
			Status:  429})
		return
	}

	// Select and parse user's authentication key and PBKDF2 salt
	var challenge Challenge
	var saltAndKey []byte
	row := DB.QueryRow("SELECT AuthKey FROM AuthKeys WHERE UserID = ?", user.ID)
	err := row.Scan(&saltAndKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	} else if len(saltAndKey) < 32 {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "The authentication key belonging to this user is currently in an unprocessable state (less than 16 bytes in length excluding salt). PATCH /authKey to fix this.",
			Status:  409})
		return
	}
	challenge.Salt = base64.StdEncoding.EncodeToString(saltAndKey[0:16])
	authKey := saltAndKey[16:]

	// Create a unique ID
	challenge.ID, err = MakeUniqueID("Challenges")
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	challenge.EncodedID = EncodeID(challenge.ID)

	// Generate 32 bytes of random data for the challenge
	challenge.Data = make([]byte, 32)
	rand.Read(challenge.Data)

	// Create a block cipher from the authkey, then encrypt the challenge's data
	block, err := aes.NewCipher(authKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	if err := challenge.encryptData(block); err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Add the challenge to the database
	_, err = DB.Exec("INSERT INTO Challenges (ID, UserID, _Data) VALUES (?, ?, ?)", challenge.ID, user.ID, challenge.Data)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	json.NewEncoder(w).Encode(challenge)
}

// SubmitChallenge - Submit an authentication challenge
func SubmitChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Enforce action verbage
	if r.URL.Query().Get("action") != "submit" {
		HTTPError(w, Error{
			Title:   "Invalid Action Parameter",
			Message: "To enforce semantics, all challenge submissions must contain '?action=submit'.",
			Status:  422})
		return
	}

	var challenge Challenge
	var user User
	json.NewDecoder(r.Body).Decode(&challenge)
	if err := HTTPValidate(w, challenge); err != nil {
		return
	}

	var err error
	challenge.ID, err = DecodeID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Missing or malformed ID provided.",
			Status:  400})
		return
	}
	challenge.Data, err = base64.StdEncoding.DecodeString(challenge.EncodedData)

	var correctData []byte
	row := DB.QueryRow("SELECT _Data, UserID FROM Challenges WHERE ID = ? AND Failed = 0", challenge.ID)
	err = row.Scan(&correctData, &user.ID)
	if err != nil {
		HTTPNotFoundError(w)
		return
	}

	// Compare lengths first to avoid range errors
	if len(challenge.Data) != len(correctData) {
		HTTPError(w, Error{
			Title:   "Challenge Failed",
			Message: "Incorrect data provided.",
			Status:  401})
		return
	}

	// If the data isn't equal to the
	for i := range correctData {
		if correctData[i] != challenge.Data[i] {
			HTTPError(w, Error{
				Title:   "Challenge Failed",
				Message: "Incorrect data provided.",
				Status:  401})
			return
		}
	}

	// At this point, the challenge is successful and the user is authorized
	user.parseDeviceInfo(r)
	// Create new tokens
	DB.Exec("DELETE FROM Challenges WHERE ID = ?", challenge.ID)
	tokens, err := user.newSession()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	user.EncodedID = EncodeID(user.ID)
	w.Header().Set("Set-Cookie", fmt.Sprintf("Authorization=%s; Path=/; HttpOnly; Max-Age=%d", tokens.Token, twoWeeks))
	json.NewEncoder(w).Encode(map[string]string{
		"id":        user.EncodedID,
		"CSRFtoken": tokens.CSRFtoken})
}
