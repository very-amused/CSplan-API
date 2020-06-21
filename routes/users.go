package routes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

// User - Authentication and identification info for a user
type User struct {
	ID             int
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required,max=60"`
	HashedPassword []byte `db:"Password"`
}

// UserState - State information for a user
type UserState struct {
	ID       int  `json:"id"`
	Verified bool `json:"verified"`
}

// Tokens - Authentication tokens for a user
type Tokens struct {
	Token     string `json:"token"`
	CSRFtoken string `json:"CSRFtoken"`
}

// TokenResponse - Response to a successful login attempt
type TokenResponse struct {
	CSRFtoken string `json:"CSRFtoken"`
}

// Scrypt Params - N, r, p, keyLen
var _N, r, p, keyLen = 32768, 9, 1, 32

// user.exists - Return true if a user with the specified email already exists
func (user *User) exists() bool {
	row := DB.QueryRow("SELECT 1 FROM Users WHERE Email = ?", user.Email)
	var result string
	err := row.Scan(&result)
	return err == nil
}

// user.hashPassword - Hash a password using scrypt
func (user *User) hashPassword() error {
	// Generate random salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	// Hash password using scrypt
	// Todo - find more secure scrypt constants
	passbytes := []byte(user.Password)
	k, err := scrypt.Key(passbytes, salt, _N, r, p, 32)
	if err != nil {
		return err
	}

	// Set the user's hashed password to s | k
	user.HashedPassword = append(salt, k...)
	return nil
}

func (user *User) hasValidPassword() bool {
	// Select and parse the user's valid scrypt hash
	err := DB.Get(&user.HashedPassword, "SELECT Password FROM Users WHERE Email = ?", user.Email)
	if err != nil {
		return false
	}
	salt := user.HashedPassword[0:16]
	k1 := user.HashedPassword[16:]

	// Replicate the Scrypt process using the correct salt and provided password
	passbytes := []byte(user.Password)
	k2, err := scrypt.Key(passbytes, salt, _N, r, p, keyLen)
	if err != nil {
		return false
	}

	// Compare k1 (the correct key) to k2 (the key produced by the user)
	if len(k1) != len(k2) { // Compare lengths first to ensure no invalid index panics
		return false
	}
	for i := range k1 {
		if k1[i] != k2[i] {
			return false
		}
	}
	return true
}

func (user *User) makeID() error {
	// Cryptographically generate 18 random bytes and write it to an unsigned int
	bytes := make([]byte, 18)
	rand.Read(bytes)
	id := int(binary.BigEndian.Uint64(bytes))
	if id < 0 {
		id = -id
	}

	// Ensure the int is 18 digits long by converting to string, slicing, and converting back to int
	strID := strconv.Itoa(id)[0:18]
	id, _ = strconv.Atoi(strID)

	user.ID = id
	return nil
}

func (user *User) insert() error {
	tx, err := DB.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Ensure that the user id is unique
	var result int
	for true {
		err := tx.Get(&result, "SELECT 1 FROM Users WHERE ID = ?", user.ID)
		if err != nil {
			break
		}
		user.ID++
	}

	// Insert into db and commit the transaction
	_, err = tx.Exec("INSERT INTO Users (ID, Email, Password) VALUES (?, ?, ?)",
		user.ID, user.Email, user.HashedPassword)
	if err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func (user *User) newTokens() (Tokens, error) {
	tx, err := DB.Beginx()
	if err != nil {
		return Tokens{}, err
	}
	defer tx.Rollback()
	// Get the user's ID from the db for identification purposes
	tx.Get(&user.ID, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	tokenBytes := make([]byte, 32)
	csrftokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	rand.Read(csrftokenBytes)

	Token := fmt.Sprintf("%s:%d", base64.URLEncoding.EncodeToString(tokenBytes), user.ID)
	CSRFtoken := base64.URLEncoding.EncodeToString(csrftokenBytes)

	// Insert the encoded tokens into the db
	_, err = tx.Exec("INSERT INTO Tokens (UserID, Token, CSRFtoken) VALUES (?, ?, ?)", user.ID, Token, CSRFtoken)
	if err != nil {
		return Tokens{}, err
	}
	tx.Commit()

	return Tokens{
		Token,
		CSRFtoken}, nil
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

	// Do stuff
	if err := user.makeID(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	if err := user.hashPassword(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	if err := user.insert(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(UserState{
		ID:       user.ID,
		Verified: false})
	return
}

// Login - Authenticate a user and send them an auth + CSRF token
func Login(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	if err := HTTPValidate(w, user); err != nil {
		return
	}

	if !user.exists() {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "This user doesn't exist",
			Status:  404})
		return
	}

	if !user.hasValidPassword() {
		HTTPError(w, Error{
			Title:   "Unauthorized",
			Message: "Incorrect password",
			Status:  401})
		return
	}

	tokens, err := user.newTokens()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	cookie := fmt.Sprintf("Authorization=%s; Max-Age=%d; HttpOnly", tokens.Token, 60*60*24*14) // Max-Age = 2 weeks
	w.Header().Add("Set-Cookie", cookie)
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(TokenResponse{
		CSRFtoken: tokens.CSRFtoken})
}
