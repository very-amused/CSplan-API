package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/very-amused/CSplan-API/core"
)

// KeyPatch - A patch to update the key used to encrypt a user's authentication challenges
type KeyPatch struct {
	Key        string      `json:"key" validate:"required,base64,max=64"`
	HashParams *HashParams `json:"hashParams" validate:"required"`
}

// UpdateKey - Update a user's authentication key
func UpdateKey(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)
	var patch KeyPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := core.ValidateStruct(patch); err != nil {
		core.WriteError(w, *err)
		return
	} else if err := patch.HashParams.Validate(); err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Validation Error",
			Message: err.Error(),
			Status:  400})
		return
	}

	// Encode hashparams
	encodedHashParams, _ := json.Marshal(patch.HashParams)
	_, err := core.DB.Exec("UPDATE AuthKeys SET AuthKey = FROM_BASE64(?), HashParams = ? WHERE UserID = ?", patch.Key, encodedHashParams, userID)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(200)
}
