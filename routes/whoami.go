package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// WhoAmI - Tell a user their ID and verification status, mainly used to confirm that a client is authenticated
func WhoAmI(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var state UserState
	DB.Get(&state, "SELECT Verified FROM Users WHERE ID = ?", user)
	state.EncodedID = EncodeID(user)
	json.NewEncoder(w).Encode(state)
}
