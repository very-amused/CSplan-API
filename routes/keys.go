package routes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// KeyPair - Cryptographic keypair for a user
type KeyPair struct {
	PublicKey       string `json:"publicKey" validate:"required,base64"`
	PublicKeyBytes  []byte `db:"PublicKey"`
	PrivateKey      string `json:"privateKey" validate:"required,base64"`
	PrivateKeyBytes []byte `db:"PrivateKey"`
	PBKDF2salt      string `validate:"required,max=255,base64"`
	PBKDF2saltBytes []byte `db:"PBKDF2salt"`
}

// KeyPairResponse - Same as KeyPair, except without private bytes members
type KeyPairResponse struct {
	PublicKey  []byte `json:"publicKey"`
	PrivateKey []byte `json:"privateKey"`
	PBKDF2salt []byte
}

func (keys *KeyPair) decode() error {
	var err error
	keys.PublicKeyBytes, err = base64.URLEncoding.DecodeString(keys.PublicKey)
	if err != nil {
		return err
	}
	keys.PrivateKeyBytes, err = base64.URLEncoding.DecodeString(keys.PrivateKey)
	if err != nil {
		return err
	}
	keys.PBKDF2saltBytes, err = base64.URLEncoding.DecodeString(keys.PBKDF2salt)
	if err != nil {
		return err
	}
	return nil
}

func (keys *KeyPair) encode() {
	keys.PublicKey = base64.URLEncoding.EncodeToString(keys.PublicKeyBytes)
	keys.PrivateKey = base64.URLEncoding.EncodeToString(keys.PrivateKeyBytes)
	keys.PBKDF2salt = base64.URLEncoding.EncodeToString(keys.PBKDF2saltBytes)
}

// AddKeys - Add keys to a user's account
func AddKeys(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var keys KeyPair
	json.NewDecoder(r.Body).Decode(&keys)
	// Validate and decode keys
	if err := HTTPValidate(w, keys); err != nil {
		return
	}
	user := ctx.Value(key("user")).(int)

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

	if err := keys.decode(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	_, err = tx.Exec("INSERT INTO CryptoKeys (UserID, PublicKey, PrivateKey, PBKDF2salt) VALUES (?, ?, ?, ?)",
		user, keys.PublicKeyBytes, keys.PrivateKeyBytes, keys.PBKDF2saltBytes)
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
	user := ctx.Value(key("user")).(int)
	var keys KeyPair
	err := DB.Get(&keys, "SELECT PublicKey, PrivateKey, PBKDF2salt FROM CryptoKeys WHERE UserID = ?", user)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested keypair was not found",
			Status:  404})
		return
	}

	// json is smart, it automatically encodes the byte arrays as urlsafe base64, so no encoding implementation is needed here
	json.NewEncoder(w).Encode(KeyPairResponse{
		PublicKey:  keys.PublicKeyBytes,
		PrivateKey: keys.PrivateKeyBytes,
		PBKDF2salt: keys.PBKDF2saltBytes})
}
