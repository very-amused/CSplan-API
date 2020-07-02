package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// KeyPair - Cryptographic keypair for a user
type KeyPair struct {
	PublicKey  string `json:"publicKey" validate:"required,base64"`
	PrivateKey string `json:"privateKey" validate:"required,base64"`
	PBKDF2salt string `validate:"required,max=255,base64"`
}

// AddKeys - Add keys to a user's account
func AddKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var keys KeyPair
	json.NewDecoder(r.Body).Decode(&keys)
	// Validate and decode keys
	if err := HTTPValidate(w, keys); err != nil {
		return
	}
	user := ctx.Value(key("user")).(uint)

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
	}
	defer tx.Rollback()

	// Existence check
	var exists int
	err = tx.Get(&exists, "SELECT 1 FROM CryptoKeys WHERE UserID = ?", user)
	if err == nil {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "A keypair already exists for this user",
			Status:  409})
		return
	}

	_, err = tx.Exec("INSERT INTO CryptoKeys (UserID, PublicKey, PrivateKey, PBKDF2salt) VALUES (?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))",
		user, keys.PublicKey, keys.PrivateKey, keys.PBKDF2salt)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	tx.Commit()

	// No checksum is needed for this particular resource
	w.WriteHeader(204)
}

// GetKeys - Retrieve a user's keypair
func GetKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var keys KeyPair
	err := DB.Get(&keys, "SELECT TO_BASE64(PublicKey) AS PublicKey, TO_BASE64(PrivateKey) AS PrivateKey, TO_BASE64(PBKDF2salt) as PBKDF2salt FROM CryptoKeys WHERE UserID = ?", user)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested keypair was not found",
			Status:  404})
		return
	}

	json.NewEncoder(w).Encode(keys)
}
