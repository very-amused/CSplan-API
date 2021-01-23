package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	core "github.com/very-amused/CSplan-API/core"
)

// User - Authentication and identification info for a user
type User struct {
	ID         uint       `json:"-"`
	EncodedID  string     `json:"id"`
	Email      string     `json:"email" validate:"required,email"`
	Verified   bool       `json:"verified"`
	DeviceInfo string     `json:"-"`
	AuthKey    string     `json:"key" validate:"required,base64,max=64"` // The AES-GCM authentication key used to provide encryption challenges for the user
	HashParams HashParams `json:"hashParams" validate:"required"`
}

// UserState - State information for a user
type UserState struct {
	EncodedID string `json:"id"`
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
	Session Session   `json:"session"`
	User    UserState `json:"user"`
}

// DeleteToken - Response to a request for account deletion
type DeleteToken struct {
	Token string `json:"token"`
}

// DeleteConfirm - Message confirming that a user's account has been completely and permanently deleted
type DeleteConfirm struct {
	Message string `json:"message"`
}

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
	{
		name:  "Firefox",
		regex: regexp.MustCompile("Firefox")},
	{
		name:  "Opera",
		regex: regexp.MustCompile("OPR")},
	{
		name:  "Chrome/Chromium",
		regex: regexp.MustCompile("Chrome")},
	{
		name:  "Safari",
		regex: regexp.MustCompile("Safari")}}
var operatingSystems = []uaOS{
	{
		name:  "iPhone",
		regex: regexp.MustCompile("iPhone")}, // iPhones MUST be tried to match before MacOS, due to the fact that their user agents often contain "like Mac OS X"
	{
		name:  "Android",
		regex: regexp.MustCompile("Android")},
	{
		name:  "Windows",
		regex: regexp.MustCompile("Windows|NT")},
	{
		name:  "MacOS",
		regex: regexp.MustCompile("Macintosh|Mac|OS X")},
	{
		name:  "Linux",
		regex: regexp.MustCompile("Linux")}}

// user.exists - Return true if a user with the specified email already exists
func (user *User) exists() bool {
	rows, err := core.DB.Query("SELECT 1 FROM Users WHERE Email = ?", user.Email)
	defer rows.Close()
	return err == nil && rows.Next()
}

// parse the user's device info in the form of ip,browser,os
// (colons can't be used as separators because of ipv6 addresses)
func (user *User) parseDeviceInfo(r *http.Request) {
	// Check if user has consented to ip logging
	var hasUserConsent bool
	var ip string
	core.DB.Get(&hasUserConsent, "SELECT EnableIPLogging FROM Settings WHERE UserID = ?", user.ID)
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
	core.DB.Get(&user.ID, "SELECT ID FROM Users WHERE Email = ?", user.Email)
	// Generate a session ID
	session.ID, e = core.MakeUniqueID("Sessions")
	if e != nil {
		return session, e
	}
	session.EncodedID = core.EncodeID(session.ID)

	session.RawToken = make([]byte, 32)
	session.RawCSRFtoken = make([]byte, 32)
	rand.Read(session.RawToken)
	rand.Read(session.RawCSRFtoken)

	// Tokens are formatted as data:userID:sessionID, ensuring the user is always identifying themselves (by ID), as well as their session
	session.Token = base64.RawURLEncoding.EncodeToString(session.RawToken) + ":" + core.EncodeID(user.ID) + ":" + core.EncodeID(session.ID)
	session.CSRFtoken = base64.RawURLEncoding.EncodeToString(session.RawCSRFtoken)
	// Insert the encoded tokens into the db
	_, e = core.DB.Exec("INSERT INTO Sessions (ID, UserID, Token, CSRFtoken, DeviceInfo) VALUES (?, ?, ?, ?, ?)", session.ID, user.ID, session.RawToken, session.RawCSRFtoken, user.DeviceInfo)
	return session, e
}

// Register - Create a new account
func Register(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	if err := core.ValidateStruct(user); err != nil {
		core.WriteError(w, *err)
		return
	}
	// Validate hash parameters
	if err := user.HashParams.Validate(); !AuthBypass && err != nil {
		core.WriteError(w, *err)
		return
	}
	// Check if the user already exists
	if user.exists() {
		core.WriteError(w, core.HTTPError{
			Title:   "Resource Conflict",
			Message: "This user already exists",
			Status:  409})
		return
	}

	// Generate the user's ID
	var err error
	user.ID, err = core.MakeUniqueID("Users")
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	user.EncodedID = core.EncodeID(user.ID)

	// Insert the user into the database
	tx, err := core.DB.Begin()
	defer tx.Rollback()
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	// Add to the users table
	_, err = tx.Exec("INSERT INTO Users (ID, Email, Verified) VALUES (?, ?, ?)", user.ID, user.Email, user.Verified)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	// Add the user's key info to the cryptokeys table
	encodedHashParams, _ := json.Marshal(user.HashParams)
	_, err = tx.Exec("INSERT INTO AuthKeys (UserID, AuthKey, HashParams) VALUES (?, FROM_BASE64(?), ?)",
		user.ID, user.AuthKey, encodedHashParams)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(UserState{
		EncodedID: user.EncodedID,
		Verified:  false})
}

// DeleteAccount - Delete a user's account
func DeleteAccount(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	confirm := r.Header.Get("X-Confirm")

	if len(confirm) > 0 {
		// Verify legitimacy of token
		var token string
		core.DB.Get(&token, "SELECT Token FROM DeleteTokens WHERE UserID = ?", user)
		if confirm != token {
			core.WriteError(w, core.HTTPError{
				Title:   "Forbidden",
				Message: "Invalid or malformed confirmation token",
				Status:  403})
			return
		}

		// Notify the user with a 500 response if any of the delete queries fail
		// If this ever happens in production, something has gone horribly wrong
		tx, err := core.DB.Begin()
		defer tx.Rollback()
		if err != nil {
			core.WriteError500(w, err)
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
			_, err := core.DB.Exec(query, user)
			if err != nil {
				core.WriteError500(w, err)
				return
			}
		}
		tx.Commit()

		json.NewEncoder(w).Encode(DeleteConfirm{
			Message: "Your account has been successfully deleted."})
	} else {
		// If there isn't a confirmation header, prompt the user for confirmation
		exists := 0
		core.DB.Get(&exists, "SELECT 1 FROM DeleteTokens WHERE UserID = ?", user)
		if exists == 1 {
			core.WriteError(w, core.HTTPError{
				Title:   "Resource Conflict",
				Message: "This user already has a delete token stored. It will be automatically cleared in approximately 5min.",
				Status:  409})
			return
		}

		// Make the user a confirmation token
		bytes := make([]byte, 32)
		_, err := rand.Read(bytes)
		if err != nil {
			core.WriteError500(w, err)
			return
		}

		// Encode token to string
		token := base64.RawURLEncoding.EncodeToString(bytes)
		_, err = core.DB.Exec("INSERT INTO DeleteTokens (UserID, Token) VALUES (?, ?)", user, token)
		if err != nil {
			core.WriteError500(w, err)
			return
		}

		json.NewEncoder(w).Encode(DeleteToken{
			Token: token})
	}
}
