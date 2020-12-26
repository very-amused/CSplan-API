package routes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func compareTokens(provided, correct []byte) (equal bool) {
	if len(provided) != len(correct) {
		return false
	}
	for i := range correct {
		if provided[i] != correct[i] {
			return false
		}
	}
	return true
}

var twoWeeks uint = 60 * 60 * 24 * 14

var authError = Error{
	Title:   "Unauthorized",
	Message: "Missing or invalid authorization token(s)",
	Status:  401}

// Authenticate - Authorize and identify a user for a authenticate route.
func Authenticate(w http.ResponseWriter, r *http.Request) (userID uint, sessionID uint, success bool) {
	var userSession Session
	tokenCookie, err := r.Cookie("Authorization")
	if err != nil {
		HTTPError(w, authError)
		return 0, 0, false
	}
	userSession.Token = tokenCookie.Value

	userSession.CSRFtoken = r.Header.Get("CSRF-Token")
	if len(userSession.CSRFtoken) == 0 && !AuthBypass {
		HTTPError(w, authError)
		return 0, 0, false
	}

	// Parse and decode both auth and CSRF tokens
	tokenParts := strings.Split(userSession.Token, ":")
	// Make sure there are exactly two segments to the tokens, both to avoid out of range errors and as a proactive guard against malformed tokens
	if len(tokenParts) != 3 {
		HTTPError(w, authError)
		return 0, 0, false
	}
	userID, err = DecodeID(tokenParts[1])
	if err != nil {
		HTTPError(w, authError)
		return 0, 0, false
	}
	sessionID, err = DecodeID(tokenParts[2])
	if err != nil {
		HTTPError(w, authError)
		return 0, 0, false
	}
	userSession.RawToken, err = base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		HTTPError(w, authError)
		return 0, 0, false
	}
	userSession.RawCSRFtoken, err = base64.RawURLEncoding.DecodeString(userSession.CSRFtoken)
	if err != nil {
		HTTPError(w, authError)
		return 0, 0, false
	}

	row := DB.QueryRow("SELECT Token, CSRFtoken FROM Sessions WHERE ID = ? AND UserID = ?", sessionID, userID)
	if err != nil {
		HTTPInternalServerError(w, err)
		return 0, 0, false
	}

	var session Session
	row.Scan(&session.RawToken, &session.RawCSRFtoken)
	// Compare tokens at a byte sensitive level to ensure they are EXACTLY accurate
	if compareTokens(userSession.RawToken, session.RawToken) &&
		(compareTokens(userSession.RawCSRFtoken, session.RawCSRFtoken) || AuthBypass) { // Don't check CSRF tokens if auth bypass is enabled
		// Update token to show most recent time of use (prevents deletion in the middle of a session)
		go DB.Exec("UPDATE Sessions SET LastUsed = ? WHERE ID = ?", time.Now().Unix(), sessionID)
		return uint(userID), uint(sessionID), true
	}

	// If the token didn't match, the user is not authenticated
	HTTPError(w, authError)
	return 0, 0, false
}

// Login - Bypass the challenge authentication system, and simply return either a 409 or a token for the account
// associated with the email sent
func Login(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if !AuthBypass {
		HTTPError(w, Error{
			Title:   "Unauthorized",
			Message: "Invalid authorization route requested. An authorization challenge must be requested and submitted.",
			Status:  401})
		return
	}

	var user User
	json.NewDecoder(r.Body).Decode(&user)
	if !user.exists() {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "This user doesn't exist.",
			Status:  404})
		return
	}

	// Select the user's ID based on their email
	DB.Get(&user, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	// Parse the user's device info and create a new session
	user.parseDeviceInfo(r)
	session, err := user.newSession()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.Header().Set("Set-Cookie", fmt.Sprintf("Authorization=%s; Max-Age=%d; HttpOnly", session.Token, twoWeeks))
	// Don't write the HttpOnly token to the JSON response, this token must be kept from javascript access
	json.NewEncoder(w).Encode(LoginState{
		Session: session,
		User: UserState{
			EncodedID: EncodeID(user.ID),
			Verified:  user.Verified},
	})
}
