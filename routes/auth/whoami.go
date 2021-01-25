package auth

import (
	"context"
	"encoding/json"
	"net/http"

	core "github.com/very-amused/CSplan-API/core"
)

// WhoAmI - Tell a user their ID and verification status, mainly used to confirm that a client is authenticated
func WhoAmI(ctx context.Context, w http.ResponseWriter, _ *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var state UserState
	core.DB.Get(&state, "SELECT Verified FROM Users WHERE ID = ?", user)
	state.EncodedID = core.EncodeID(user)
	json.NewEncoder(w).Encode(state)
}
