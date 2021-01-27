package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	core "github.com/very-amused/CSplan-API/core"
	"github.com/very-amused/CSplan-API/routes/auth"
)

// Keys - Cryptographic keypair for a user
type Keys struct {
	PublicKey  string `json:"publicKey" validate:"required,base64"`
	PrivateKey string `json:"privateKey" validate:"required,base64"`
	// Salt passed to a hash function to generate the PrivateKey decryption key
	HashSalt   string           `json:"hashSalt" validate:"required,max=255,base64"`
	HashParams *auth.HashParams `json:"hashParams,omitempty" validate:"required"`
}

// KeysPatch - A patch to the user's KDF salt and/or RSA master keypair
type KeysPatch struct {
	PublicKey  *string          `json:"publicKey,omitempty" validate:"omitempty,base64"`
	PrivateKey *string          `json:"privateKey,omitempty" validate:"omitempty,base64"`
	HashSalt   *string          `json:"hashSalt,omitempty" validate:"omitempty,max=255,base64"`
	HashParams *auth.HashParams `json:"hashParams,omitempty"`
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
	encodedHashParams, err := json.Marshal(keys.HashParams)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	_, err = core.DB.Exec("INSERT INTO CryptoKeys (UserID, PublicKey, PrivateKey, HashSalt, HashParams) VALUES (?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?), ?)",
		user, keys.PublicKey, keys.PrivateKey, keys.HashSalt, encodedHashParams)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(201)
}

// GetKeys - Retrieve a user's key information
func GetKeys(ctx context.Context, w http.ResponseWriter, _ *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)
	var keys Keys
	var encodedHashParams []byte
	row := core.DB.QueryRow("SELECT TO_BASE64(PublicKey), TO_BASE64(PrivateKey), TO_BASE64(HashSalt), HashParams FROM CryptoKeys WHERE UserID = ?", userID)
	err := row.Scan(&keys.PublicKey, &keys.PrivateKey, &keys.HashSalt, &encodedHashParams)
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Not Found",
			Message: "The requested keypair was not found",
			Status:  404})
		return
	}
	json.Unmarshal(encodedHashParams, &keys.HashParams)

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

	var updateQuery []string
	var updateValues []interface{}

	// If hash params are being updated, the user's private key must also be updated because different hash params will produce a different key, and therefore differently encrypted data
	if patch.HashSalt != nil && patch.HashParams != nil && patch.PrivateKey != nil {
		// Validate hash params
		if err := patch.HashParams.Validate(); err != nil {
			core.WriteError(w, *err)
			return
		}

		// Encode hash params
		encodedHashParams, err := json.Marshal(patch.HashParams)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
		updateQuery = append(updateQuery, []string{
			"HashSalt = FROM_BASE64(?)",
			"HashParams = ?",
			"PrivateKey = FROM_BASE64(?)"}...)
		updateValues = append(updateValues, []interface{}{
			*patch.HashSalt,
			encodedHashParams,
			*patch.PrivateKey}...)

		// The user may also have specified an update to the public key
		if patch.PublicKey != nil {
			updateQuery = append(updateQuery, "PublicKey = FROM_BASE64(?)")
			updateValues = append(updateValues, *patch.PublicKey)
		}
		// The other possible patch here would be if the user is updating their master keypair without any changes to their hashParams
	} else if patch.PrivateKey != nil && patch.PublicKey != nil {
		updateQuery = append(updateQuery, []string{
			"PrivateKey = FROM_BASE64(?)",
			"PublicKey = FROM_BASE64(?)"}...)
		updateValues = append(updateValues, []interface{}{
			*patch.PrivateKey,
			*patch.PublicKey}...)
	} else {
		// Send the client a 412, indicating that no changes were made due to a failed precondition
		w.WriteHeader(412)
		return
	}

	_, err := core.DB.Exec(
		fmt.Sprintf("UPDATE CryptoKeys SET %s WHERE UserID = ?", strings.Join(updateQuery, ",")),
		append(updateValues, userID)...)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(200)
}
