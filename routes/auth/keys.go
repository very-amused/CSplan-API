package auth

import (
	"context"
	"encoding/json"
	"net/http"

	core "github.com/very-amused/CSplan-API/core"
)

// KeyPatch - A patch to update the key used to encrypt a user's authentication challenges
type KeyPatch struct {
	Key string `json:"key" validate:"required,base64,min=32"`
}

// UpdateKey - Update a user's authentication key
func UpdateKey(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var patch KeyPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := core.ValidateStruct(patch); err != nil {
		core.WriteError(w, *err)
		return
	}

	_, err := core.DB.Exec("UPDATE AuthKeys SET AuthKey = FROM_BASE64(?) WHERE UserID = ?", patch.Key, user)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(204)
}
