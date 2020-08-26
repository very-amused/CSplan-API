package routes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// User - Authentication and identification info for a user
type User struct {
	ID        uint    `json:"-"`
	EncodedID string  `json:"id"`
	Email     string  `json:"email" validate:"required,email"`
	Verfied   bool    `json:"verified"`
	Keys      KeyInfo `json:"keys"`
}

// UserState - State information for a user
type UserState struct {
	EncodedID string `json:"id"`
	Verified  bool   `json:"verified"`
}

// Challenge - RSA challenge to obtain authentication
type Challenge struct {
	ID            uint   `json:"-"`
	EncodedID     string `json:"id"`
	Data          []byte `json:"-"`
	EncryptedData string `json:"data"`
}

// Tokens - Authentication tokens for a user
type Tokens struct {
	Token     string `json:"-"`
	CSRFtoken string
}

// LoginState - State information for a user as a response to a login request
type LoginState struct {
	Tokens
	UserState
}

// DeleteToken - Response to a request for account deletion
type DeleteToken struct {
	Token string `json:"token"`
}

// DeleteConfirm - Message confirming that a user's account has been completely and permanently deleted
type DeleteConfirm struct {
	Message string `json:"message"`
}

// Scrypt Params - N, r, p, keyLen
var _N, r, p, keyLen = 32768, 9, 1, 32

// user.exists - Return true if a user with the specified email already exists
func (user *User) exists() bool {
	exists := 0
	DB.Get(&exists, "SELECT 1 FROM Users WHERE Email = ?", user.Email)
	return exists == 1
}

func (user *User) newTokens() (Tokens, error) {
	// Get the user's ID from the db for identification purposes
	DB.Get(&user.ID, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	tokenBytes := make([]byte, 32)
	csrftokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	rand.Read(csrftokenBytes)

	Token := fmt.Sprintf("%s:%d", base64.RawURLEncoding.EncodeToString(tokenBytes), user.ID)
	CSRFtoken := base64.RawURLEncoding.EncodeToString(csrftokenBytes)

	// Insert the encoded tokens into the db
	_, err := DB.Exec("INSERT INTO Tokens (UserID, Token, CSRFtoken) VALUES (?, ?, ?)", user.ID, Token, CSRFtoken)

	return Tokens{
		Token,
		CSRFtoken}, err
}

// Register - Create a new account
func Register(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	if err := HTTPValidate(w, user); err != nil {
		return
	}

	// Check if the user already exists
	if user.exists() {
		HTTPError(w, Error{
			Title:   "Conflict",
			Message: "This user already exists",
			Status:  409})
		return
	}

	// Generate the user's ID
	for {
		user.ID = MakeID()
		rows, err := DB.Query("SELECT 1 FROM Users WHERE ID = ?", user.ID)
		defer rows.Close()
		if !rows.Next() {
			break
		} else {
			if err != nil {
				HTTPInternalServerError(w, err)
				return
			}
			user.ID++
		}
	}
	user.EncodedID = EncodeID(user.ID)

	// Insert the user into the database
	tx, err := DB.Beginx()
	defer tx.Rollback()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Add to the users table
	_, err = tx.Exec("INSERT INTO Users (ID, Email, Verified) VALUES (?, ?, ?)", user.ID, user.Email, user.Verfied)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Add the user's key info to the cryptokeys table
	_, err = tx.Exec("INSERT INTO CryptoKeys (UserID, PBKDF2salt, PublicKey) VALUES (?, FROM_BASE64(?), FROM_BASE64(?))",
		user.ID, user.Keys.PBKDF2salt, user.Keys.PublicKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(UserState{
		EncodedID: user.EncodedID,
		Verified:  false})
}

// DeleteAccount - Delete a user's account
func DeleteAccount(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	confirm := r.Header.Get("X-Confirm")

	if len(confirm) > 0 {
		// Verify legitimacy of token
		var token string
		DB.Get(&token, "SELECT Token FROM DeleteTokens WHERE UserID = ?", user)
		if confirm != token {
			HTTPError(w, Error{
				Title:   "Forbidden",
				Message: "Invalid or malformed confirmation token",
				Status:  403})
			return
		}

		// Notify the user with a 500 response if any of the delete queries fail
		// If this ever happens in production, something has gone horribly wrong
		queries := []string{
			"DELETE FROM TodoLists WHERE UserID = ?",
			"DELETE FROM Names WHERE UserID = ?",
			"DELETE FROM CryptoKeys WHERE UserID = ?",
			"DELETE FROM DeleteTokens WHERE UserID = ?",
			"DELETE FROM Tokens WHERE UserID = ?",
			"DELETE FROM NoList WHERE UserID = ?",
			"DELETE FROM Users WHERE ID = ?"}
		for _, query := range queries {
			_, err := DB.Exec(query, user)
			if err != nil {
				HTTPInternalServerError(w, err)
				return
			}
		}

		json.NewEncoder(w).Encode(DeleteConfirm{
			Message: "Your account has been successfully deleted."})
	} else {
		// If there isn't a confirmation header, prompt the user for confirmation
		exists := 0
		DB.Get(&exists, "SELECT 1 FROM DeleteTokens WHERE UserID = ?", user)
		if exists == 1 {
			HTTPError(w, Error{
				Title:   "Resource Conflict",
				Message: "This user already has a delete token stored. It will be automatically cleared in approximately 5min.",
				Status:  409})
			return
		}

		// Make the user a confirmation token
		bytes := make([]byte, 32)
		_, err := rand.Read(bytes)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		// Encode token to string
		token := base64.RawURLEncoding.EncodeToString(bytes)
		_, err = DB.Exec("INSERT INTO DeleteTokens (UserID, Token) VALUES (?, ?)", user, token)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		json.NewEncoder(w).Encode(DeleteToken{
			Token: token})
	}
}
