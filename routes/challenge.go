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
)

// ChallengeRoute - Parse the challenge action from query parameters and continue with the appropriate route
func ChallengeRoute(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	switch params.Get("action") {
	case "request":
		RequestChallenge(ctx, w, r)
	case "submit":
		SubmitChallenge(ctx, w, r)
	default:
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "The requested challenge action is either invalid or missing.",
			Status:  409})
		return
	}
}

// RequestChallenge - Request an authentication challenge
func RequestChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request) {
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

	// Generate 16 bytes of random data for the challenge
	var challenge Challenge
	challenge.ID = MakeID()
	// TODO: ensure challenge IDs are unique
	challenge.EncodedID = EncodeID(challenge.ID)
	challenge.Data = make([]byte, 16)
	rand.Read(challenge.Data)

	// Select the user's public key and PBKDF2 salt
	var authKey []byte
	row := DB.QueryRow("SELECT AuthKey FROM AuthKeys WHERE UserID = ?", user.ID)
	err := row.Scan(&authKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Parse the user's public RSA key
	block, err := aes.NewCipher(authKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	// Create a tag for GCM encryption
	iv := make([]byte, 12)
	rand.Read(iv)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	encrypted := gcm.Seal(nil, iv, challenge.Data, nil)
	challenge.EncryptedData = base64.StdEncoding.EncodeToString(encrypted)

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
	fmt.Println("challenge submitted")
}
