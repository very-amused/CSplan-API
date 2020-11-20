package routes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// User - Authentication and identification info for a user
type User struct {
	ID         uint   `json:"-"`
	EncodedID  string `json:"id"`
	Email      string `json:"email" validate:"required,email"`
	Verified   bool   `json:"verified"`
	DeviceInfo string `json:"-"`
	AuthKey    string `json:"key" validate:"required"` // The AES-GCM authentication key used to provide encryption challenges for the user
}

// UserState - State information for a user
type UserState struct {
	EncodedID string `json:"userID"`
	Verified  bool   `json:"verified"`
}

// Session - Authentication tokens for a user
type Session struct {
	ID           uint   `json:"-"`
	EncodedID    string `json:"id"`
	RawToken     []byte `json:"-"`
	Token        string `json:"-"`
	RawCSRFtoken []byte `json:"-"`
	CSRFtoken    string
}

// LoginState - State information for a user as a response to a login request
type LoginState struct {
	Session
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

// Regexes for parsing user device and browser
type useragentMatch struct {
	name  string
	regex *regexp.Regexp
}

// User agent browser info
type uaBrowser useragentMatch

// User agent OS info
type uaOS useragentMatch

// The order of these is VERY SPECIFIC... Opera user agents will match for Opera, Chrome and Safari, Chrome user agents will match for both Chrome and Safari, so these regexes must be checked in the order presented to not incorrectly identify Opera and Chrome as Safari, or Opera as Chrome
var browsers = []uaBrowser{
	uaBrowser{
		name:  "Firefox",
		regex: regexp.MustCompile("Firefox")},
	uaBrowser{
		name:  "Opera",
		regex: regexp.MustCompile("OPR")},
	uaBrowser{
		name:  "Chrome/Chromium",
		regex: regexp.MustCompile("Chrome")},
	uaBrowser{
		name:  "Safari",
		regex: regexp.MustCompile("Safari")}}
var operatingSystems = []uaOS{
	uaOS{
		name:  "iPhone",
		regex: regexp.MustCompile("iPhone")}, // iPhones MUST be tried to match before MacOS, due to the fact that their user agents often contain "like Mac OS X"
	uaOS{
		name:  "Android",
		regex: regexp.MustCompile("Android")},
	uaOS{
		name:  "Windows",
		regex: regexp.MustCompile("Windows|NT")},
	uaOS{
		name:  "MacOS",
		regex: regexp.MustCompile("Macintosh|Mac|OS X")},
	uaOS{
		name:  "Linux",
		regex: regexp.MustCompile("Linux")}}

// user.exists - Return true if a user with the specified email already exists
func (user *User) exists() bool {
	exists := 0
	DB.Get(&exists, "SELECT 1 FROM Users WHERE Email = ?", user.Email)
	return exists == 1
}

// parse the user's device info in the form of ip,browser,os
// (colons can't be used as separators because of ipv6 addresses)
func (user *User) parseDeviceInfo(r *http.Request) {
	// Check if user has consented to ip logging
	var hasUserConsent bool
	var ip string
	DB.Get(&hasUserConsent, "SELECT EnableIPLogging FROM Settings WHERE UserID = ?", user.ID)
	// Parse user ip address
	if hasUserConsent {
		// Check X-FORWARDED-FOR header, then fallback to raw address if that fails
		if ip = r.Header.Get("X-Forwarded-For"); len(ip) == 0 {
			ip = r.RemoteAddr
		}
		// Trim the port from the ip
		parts := strings.Split(ip, ":")
		ip = strings.Join(parts[:len(parts)-1], ":")
	} else {
		ip = "Disabled"
	}

	// Get user operating system via regex matching for useragent string
	var userAgent = r.Header.Get("User-Agent")
	var browser string
	for _, b := range browsers {
		if b.regex.MatchString(userAgent) {
			browser = b.name
			break
		}
	}
	// If no browser was able to be parsed, set browser as 'Unknown'
	if len(browser) == 0 {
		browser = "Unknown"
	}

	// TODO: Repeat the same process for parsing the user's OS
	var os string
	for _, o := range operatingSystems {
		if o.regex.MatchString(userAgent) {
			os = o.name
			break
		}
	}
	// If no OS was able to be parsed, set as Unknown
	if len(os) == 0 {
		os = "Unknown"
	}

	user.DeviceInfo = fmt.Sprintf("%s,%s,%s", ip, browser, os)
}

func (user *User) newSession() (session Session, e error) {
	// Get the user's ID from the db for identification purposes
	DB.Get(&user.ID, "SELECT ID FROM Users WHERE Email = ?", user.Email)
	// Generate a session ID
	session.ID, e = MakeUniqueID("Sessions")
	if e != nil {
		return session, e
	}
	session.EncodedID = EncodeID(session.ID)

	session.RawToken = make([]byte, 32)
	session.RawCSRFtoken = make([]byte, 32)
	rand.Read(session.RawToken)
	rand.Read(session.RawCSRFtoken)

	session.Token = base64.RawURLEncoding.EncodeToString(session.RawToken) + ":" + EncodeID(user.ID)
	session.CSRFtoken = base64.RawURLEncoding.EncodeToString(session.RawCSRFtoken)
	// Insert the encoded tokens into the db
	_, e = DB.Exec("INSERT INTO Sessions (ID, UserID, Token, CSRFtoken, DeviceInfo) VALUES (?, ?, ?, ?, ?)", session.ID, user.ID, session.RawToken, session.RawCSRFtoken, user.DeviceInfo)
	return session, e
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
	tx, err := DB.Begin()
	defer tx.Rollback()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Add to the users table
	_, err = tx.Exec("INSERT INTO Users (ID, Email, Verified) VALUES (?, ?, ?)", user.ID, user.Email, user.Verified)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Add the user's key info to the cryptokeys table
	_, err = tx.Exec("INSERT INTO AuthKeys (UserID, AuthKey) VALUES (?, FROM_BASE64(?))",
		user.ID, user.AuthKey)
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
		tx, err := DB.Begin()
		defer tx.Rollback()
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
		queries := []string{
			"DELETE FROM TodoLists WHERE UserID = ?",
			"DELETE FROM Names WHERE UserID = ?",
			"DELETE FROM AuthKeys WHERE UserID = ?",
			"DELETE FROM CryptoKeys WHERE UserID = ?",
			"DELETE FROM DeleteTokens WHERE UserID = ?",
			"DELETE FROM Sessions WHERE UserID = ?",
			"DELETE FROM Challenges WHERE UserID = ?",
			"DELETE FROM NoList WHERE UserID = ?",
			"DELETE FROM Settings WHERE UserID = ?",
			"DELETE FROM Users WHERE ID = ?"}
		for _, query := range queries {
			_, err := DB.Exec(query, user)
			if err != nil {
				HTTPInternalServerError(w, err)
				return
			}
		}
		tx.Commit()

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
