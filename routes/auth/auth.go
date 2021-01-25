package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	core "github.com/very-amused/CSplan-API/core"
)

/* Authentication levels for this API serve as follows:
Level -1: Tried to access a route requiring greater authorization than provided, return 401
Level 0: Authorized to participate in the process of upgrading auth to a higher level
Level 1: Authorized to perform actions concerning the current session, view and modify resources (obtained through solving challenges such as TOTP and AES decryption)
Level 2: Authorized to perform actions regarding other sessions, such as remote logout and lockdown (obtained through reverifying their current session by TOTP or email)
*/

// Info - Information authorizing a user to perform certain actions with the API
type Info struct {
	UserID    uint
	SessionID uint
	AuthLevel int
}

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
var (
	// AuthBypass - Enable to bypass normal authentication
	AuthBypass = false

	// HTTPUnauthorized - User is not authorized entirely
	HTTPUnauthorized = core.HTTPError{
		Title:   "Unauthorized",
		Message: "Missing or invalid authorization token(s)",
		Status:  401}
	// HTTPForbidden - User is authorized, but for the requested route
	HTTPForbidden = core.HTTPError{
		Title:   "Forbidden",
		Message: "Insufficient authentication level for the requested route",
		Status:  403}
	unauthorized = Info{
		AuthLevel: -1}
)

// Authenticate - Authorize and identify a user for a authenticate route.
func Authenticate(r *http.Request) Info {
	var userSession Session
	tokenCookie, err := r.Cookie("Authorization")
	if err != nil {
		return unauthorized
	}
	userSession.Token = tokenCookie.Value

	userSession.CSRFtoken = r.Header.Get("CSRF-Token")
	if len(userSession.CSRFtoken) == 0 && !AuthBypass {
		return unauthorized
	}

	// Parse and decode both auth and CSRF tokens
	tokenParts := strings.Split(userSession.Token, ":")
	// Make sure there are exactly two segments to the tokens, both to avoid out of range errors and as a proactive guard against malformed tokens
	if len(tokenParts) != 3 {
		return unauthorized
	}
	userID, err := core.DecodeID(tokenParts[1])
	if err != nil {
		return unauthorized
	}
	sessionID, err := core.DecodeID(tokenParts[2])
	if err != nil {
		return unauthorized
	}
	userSession.RawToken, err = base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return unauthorized
	}
	userSession.RawCSRFtoken, err = base64.RawURLEncoding.DecodeString(userSession.CSRFtoken)
	if err != nil {
		return unauthorized
	}

	row := core.DB.QueryRow("SELECT Token, CSRFtoken FROM Sessions WHERE ID = ? AND UserID = ?", sessionID, userID)

	var session Session
	row.Scan(&session.RawToken, &session.RawCSRFtoken)
	// Compare tokens at a byte sensitive level to ensure they are EXACTLY accurate
	if compareTokens(userSession.RawToken, session.RawToken) &&
		(compareTokens(userSession.RawCSRFtoken, session.RawCSRFtoken) || AuthBypass) { // Don't check CSRF tokens if auth bypass is enabled
		// Update token to show most recent time of use (prevents deletion in the middle of a session)
		go core.DB.Exec("UPDATE Sessions SET LastUsed = ? WHERE ID = ?", time.Now().Unix(), sessionID)
		return Info{
			UserID:    userID,
			SessionID: sessionID,
			AuthLevel: 1}
	}

	// If the token didn't match, the user is not authenticated
	return unauthorized
}

// Login - Bypass the challenge authentication system, and simply return either a 409 or a token for the account
// associated with the email sent
func Login(_ context.Context, w http.ResponseWriter, r *http.Request) {
	if !AuthBypass {
		core.WriteError(w, core.HTTPError{
			Title:   "Unauthorized",
			Message: "Invalid authorization route requested. An authorization challenge must be requested and submitted.",
			Status:  401})
		return
	}

	var user User
	json.NewDecoder(r.Body).Decode(&user)
	if !user.exists() {
		core.WriteError(w, core.HTTPError{
			Title:   "Not Found",
			Message: "This user doesn't exist.",
			Status:  404})
		return
	}

	// Select the user's ID based on their email
	core.DB.Get(&user, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	// Parse the user's device info and create a new session
	user.parseDeviceInfo(r)
	session, err := user.newSession()
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.Header().Set("Set-Cookie", fmt.Sprintf("Authorization=%s; Max-Age=%d; HttpOnly", session.Token, twoWeeks))
	// Don't write the HttpOnly token to the JSON response, this token must be kept from javascript access
	json.NewEncoder(w).Encode(UserState{
		EncodedID: core.EncodeID(user.ID),
		Verified:  user.Verified})
}
