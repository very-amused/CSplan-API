package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	core "github.com/very-amused/CSplan-API/core"
)

// SessionInfo - Information identifying a session without giving away any authentication details
type SessionInfo struct {
	ID         uint   `json:"-"`
	EncodedID  string `json:"id"`
	DeviceInfo string `json:"deviceInfo"`
	Created    uint   `json:"created"`
	LastUsed   uint   `json:"lastUsed"`
	Expired    bool   `json:"expired"`
	AuthLevel  int    `json:"authLevel"`
}

// GetSessions - Get a list of active sessions
func GetSessions(ctx context.Context, w http.ResponseWriter, _ *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)
	sessionID := ctx.Value(core.Key("session")).(uint)

	rows, err := core.DB.Query("SELECT ID, DeviceInfo, Created, LastUsed FROM Sessions WHERE UserID = ?", userID)
	defer rows.Close()
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	var sessions []SessionInfo
	i := 0
	for rows.Next() {
		session := SessionInfo{
			AuthLevel: 1}
		rows.Scan(&session.ID, &session.DeviceInfo, &session.Created, &session.LastUsed)
		session.EncodedID = core.EncodeID(session.ID)
		// This flag is to inform clients to log the user out as soon as possible, so that the session can be automatically cleared
		// (or clear it manually using an API call)
		if uint(time.Now().Unix())-session.Created >= twoWeeks {
			session.Expired = true
		}
		sessions = append(sessions, session)
		// Send an X-Current-Session header indicating the position (starting at 0) of the current session in the response body
		// This is a simpler and more efficient solution than either forcing clients to store session IDs and keep track of this on their own
		// or tagging each session with a bool (that will have the same value for all but one of them)
		if session.ID == sessionID {
			w.Header().Set("X-Current-Session", strconv.Itoa(i))
		}
		i++
	}
	json.NewEncoder(w).Encode(sessions)
}

// Logout - Log out from either a session specified by parameter, or the currently active session
func Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)
	sessionID := ctx.Value(core.Key("session")).(uint)
	idParam := mux.Vars(r)["id"]

	// If no session ID is provided, assume logging out from current session
	var err error
	if len(idParam) == 0 {
		core.DB.Exec("DELETE FROM Sessions WHERE ID = ?", sessionID)
	} else {
		sessionID, err := core.DecodeID(idParam)
		if err != nil {
			core.WriteError(w, core.HTTPError{
				Title:   "Bad Request",
				Message: "Malformed id param",
				Status:  400})
			return
		}
		core.DB.Exec("DELETE FROM Sessions WHERE ID = ? AND UserID = ?", sessionID, userID)
	}
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(204)
}
