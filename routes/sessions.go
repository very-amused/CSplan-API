package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// GetSessions - Get a list of active sessions
func GetSessions(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID := ctx.Value(key("user")).(uint)

	rows, err := DB.Query("SELECT ID, DeviceInfo, Created, LastUsed FROM Sessions WHERE UserID = ?", userID)
	defer rows.Close()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	var sessions []SessionInfo
	for rows.Next() {
		session := SessionInfo{
			AuthLevel: 1}
		rows.Scan(&session.ID, &session.DeviceInfo, &session.Created, &session.LastUsed)
		session.EncodedID = EncodeID(session.ID)
		// This flag is to inform clients to log the user out as soon as possible, so that the session can be automatically cleared
		// (or clear it manually using an API call)
		if uint(time.Now().Unix())-session.Created >= twoWeeks {
			session.Expired = true
		}
		sessions = append(sessions, session)
	}
	json.NewEncoder(w).Encode(sessions)
}

// Logout - Log out from either a session specified by parameter, or the currently active session
func Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID := ctx.Value(key("user")).(uint)
	sessionID := ctx.Value(key("session")).(uint)
	idParam := mux.Vars(r)["id"]

	// If no session ID is provided, assume logging out from current session
	var err error
	if len(idParam) == 0 {
		DB.Exec("DELETE FROM Sessions WHERE ID = ?", sessionID)
	} else {
		sessionID, err := DecodeID(idParam)
		if err != nil {
			HTTPError(w, Error{
				Title:   "Bad Request",
				Message: "Malformed id param",
				Status:  400})
			return
		}
		DB.Exec("DELETE FROM Sessions WHERE ID = ? AND UserID = ?", sessionID, userID)
	}
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.WriteHeader(204)
}
