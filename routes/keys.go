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

// TODO: add route to update keys
