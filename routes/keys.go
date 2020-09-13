package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// CryptoKeys - Cryptographic keypair for a user
type CryptoKeys struct {
	PublicKey  string `json:"publicKey" validate:"required,base64"`
	PrivateKey string `json:"privateKey" validate:"required,base64"`
	PBKDF2salt string `validate:"required,max=255,base64"`
}

type cryptoKeysPatch struct {
	PublicKey  string `json:"publicKey" validate:"omitempty,base64"`
	PrivateKey string `json:"privateKey" validate:"omitempty,base64"`
	PBKDF2salt string `validate:"omitempty,max=255,base64"`
}

// AddKeys - Create a user's keypair
func AddKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var keys CryptoKeys
	json.NewDecoder(r.Body).Decode(&keys)
	if err := HTTPValidate(w, keys); err != nil {
		return
	}

	// Insert the keys into the DB
	_, err := DB.Exec("INSERT INTO CryptoKeys (UserID, PublicKey, PrivateKey, PBKDF2salt) VALUES (?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))",
		user, keys.PublicKey, keys.PrivateKey, keys.PBKDF2salt)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// There is no need to provide a checksum or any meta information for these keys to assist with caching,
	// as caching a user's master keypair would be a security vulnerability
	w.WriteHeader(201)
}

// GetKeys - Retrieve a user's key information
func GetKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var keys CryptoKeys
	err := DB.Get(&keys, "SELECT TO_BASE64(PublicKey) AS PublicKey, TO_BASE64(PrivateKey) AS PrivateKey, TO_BASE64(PBKDF2salt) AS PBKDF2salt FROM CryptoKeys WHERE UserID = ?", user)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested keypair was not found",
			Status:  404})
		return
	}

	json.NewEncoder(w).Encode(keys)
}

// UpdateKeys - Update a user's cryptographic keypair
func UpdateKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	// Existence check
	rows, _ := DB.Query("SELECT 1 FROM CryptoKeys WHERE UserID = ?", user)
	defer rows.Close()
	if !rows.Next() {
		HTTPNotFoundError(w)
		return
	}

	// Decode patches and verify
	var patch cryptoKeysPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	// Apply any updates specified as a transaction
	tx, err := DB.Begin()
	defer tx.Rollback()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	errs := make([]error, 3)
	if len(patch.PublicKey) > 0 {
		_, errs[0] = tx.Exec("UPDATE CryptoKeys SET PublicKey = FROM_BASE64(?) WHERE UserID = ?", patch.PublicKey, user)
	}
	if len(patch.PrivateKey) > 0 {
		_, errs[1] = tx.Exec("UPDATE CryptoKeys SET PrivateKey = FROM_BASE64(?) WHERE UserID = ?", patch.PrivateKey, user)
	}
	if len(patch.PBKDF2salt) > 0 {
		_, errs[2] = tx.Exec("UPDATE CryptoKeys SET PBKDF2salt = FROM_BASE64(?) WHERE UserID = ?", patch.PBKDF2salt, user)
	}
	for _, err := range errs {
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}
	tx.Commit()

	w.WriteHeader(204)
}
