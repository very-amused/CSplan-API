package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// KeyInfo - Cryptographic keypair for a user
type KeyInfo struct {
	PublicKey  string `json:"publicKey" validate:"required,base64"`
	PBKDF2salt string `validate:"required,max=255,base64"`
}

// AddKeys - Add keys to a user's account
func AddKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var keys KeyInfo
	json.NewDecoder(r.Body).Decode(&keys)
	// Validate and decode keys
	var err error
	if err := HTTPValidate(w, keys); err != nil {
		return
	}
	user := ctx.Value(key("user")).(uint)

	if err != nil {
		HTTPInternalServerError(w, err)
	}

	// Existence check
	var exists int
	err = DB.Get(&exists, "SELECT 1 FROM CryptoKeys WHERE UserID = ?", user)
	if err == nil {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "A keypair already exists for this user",
			Status:  409})
		return
	}

	_, err = DB.Exec("INSERT INTO CryptoKeys (UserID, PublicKey, PBKDF2salt) VALUES (?, FROM_BASE64(?), FROM_BASE64(?))",
		user, keys.PublicKey, keys.PBKDF2salt)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// No checksum is needed for this particular resource
	w.WriteHeader(204)
}

// GetKeys - Retrieve a user's key information
func GetKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var keys KeyInfo
	err := DB.Get(&keys, "SELECT TO_BASE64(PublicKey) AS PublicKey, TO_BASE64(PBKDF2salt) as PBKDF2salt FROM CryptoKeys WHERE UserID = ?", user)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested keypair was not found",
			Status:  404})
		return
	}

	json.NewEncoder(w).Encode(keys)
}
