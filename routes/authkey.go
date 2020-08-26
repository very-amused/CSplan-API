package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// AuthKeyPatch - A patch to update the key used to encrypt a user's authentication challenges
type AuthKeyPatch struct {
	AuthKey string `json:"key" validate:"required,base64"`
}

// UpdateAuthKey - Update a user's authentication key
func UpdateAuthKey(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var patch AuthKeyPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	_, err := DB.Exec("UPDATE AuthKeys SET AuthKey = FROM_BASE64(?) WHERE UserID = ?", patch.AuthKey, user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.WriteHeader(204)
}
