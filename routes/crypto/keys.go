package crypto

import (
	"context"
	"encoding/json"
	"net/http"

	core "github.com/very-amused/CSplan-API/core"
)

// Keys - Cryptographic keypair for a user
type Keys struct {
	PublicKey  string `json:"publicKey" validate:"required,base64"`
	PrivateKey string `json:"privateKey" validate:"required,base64"`
	PBKDF2salt string `validate:"required,max=255,base64"`
}

// KeysPatch - A patch to the user's KDF salt and/or RSA master keypair
type KeysPatch struct {
	PublicKey  string `json:"publicKey" validate:"omitempty,base64"`
	PrivateKey string `json:"privateKey" validate:"omitempty,base64"`
	PBKDF2salt string `validate:"omitempty,base64"`
}

// AddKeys - Create a user's keypair
func AddKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var keys Keys
	json.NewDecoder(r.Body).Decode(&keys)
	if err := core.ValidateStruct(keys); err != nil {
		core.WriteError(w, *err)
		return
	}

	// Insert the keys into the DB
	_, err := core.DB.Exec("INSERT INTO CryptoKeys (UserID, PublicKey, PrivateKey, PBKDF2salt) VALUES (?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))",
		user, keys.PublicKey, keys.PrivateKey, keys.PBKDF2salt)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(201)
}

// GetKeys - Retrieve a user's key information
func GetKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var keys Keys
	err := core.DB.Get(&keys, "SELECT TO_BASE64(PublicKey) AS PublicKey, TO_BASE64(PrivateKey) AS PrivateKey, TO_BASE64(PBKDF2salt) AS PBKDF2salt FROM CryptoKeys WHERE UserID = ?", user)
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Not Found",
			Message: "The requested keypair was not found",
			Status:  404})
		return
	}

	json.NewEncoder(w).Encode(keys)
}

// UpdateKeys - Update a user's cryptographic keypair
func UpdateKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)
	// Existence check
	rows, _ := core.DB.Query("SELECT 1 FROM CryptoKeys WHERE UserID = ?", userID)
	defer rows.Close()
	if !rows.Next() {
		core.WriteError404(w)
		return
	}

	// Decode patches and verify
	var patch KeysPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := core.ValidateStruct(patch); err != nil {
		core.WriteError(w, *err)
		return
	}

	// Apply any updates specified as a transaction
	tx, err := core.DB.Begin()
	defer tx.Rollback()
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	errs := make([]error, 2)
	// RSA keys must be both patched at the same time
	if len(patch.PrivateKey) > 0 && len(patch.PublicKey) > 0 {
		_, errs[0] = tx.Exec("UPDATE CryptoKeys SET PrivateKey = FROM_BASE64(?), PublicKey = FROM_BASE64(?) WHERE UserID = ?",
			patch.PrivateKey, patch.PublicKey, userID)
	}
	if len(patch.PBKDF2salt) > 0 {
		_, errs[1] = tx.Exec("UPDATE CryptoKeys SET PBKDF2salt = FROM_BASE64(?) WHERE UserID = ?", patch.PBKDF2salt, userID)
	}
	for _, err := range errs {
		if err != nil {
			core.WriteError500(w, err)
			return
		}
	}
	tx.Commit()

	w.WriteHeader(200)
}
