package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// Settings - Settings used to apply user consent safeguards to operations that may be undesired
type Settings struct {
	UserID          uint  `json:"-"`
	EnableIPLogging *bool `json:"enableIPLogging"`
	EnableReminders *bool `json:"enableReminders"`
}

func (settings *Settings) get() error {
	err := DB.Get(settings, "SELECT EnableIPLogging, EnableReminders FROM Settings WHERE UserID = ?", settings.UserID)
	return err
}

func (settings Settings) update() {
	// Check if pointers are not nil to avoid letting go's typesafety cause unwanted changes
	if settings.EnableIPLogging != nil {
		DB.Exec("UPDATE Settings SET EnableIPLogging = ?", settings.EnableIPLogging)
	}
	if settings.EnableReminders != nil {
		DB.Exec("UPDATE Settings SET EnableReminders = ?", settings.EnableReminders)
	}
}

// GetSettings - Retrieve a user's privacy settings
func GetSettings(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var settings Settings
	settings.UserID = ctx.Value(key("user")).(uint)
	if err := settings.get(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	json.NewEncoder(w).Encode(settings)
}

// UpdateSettings - Update a user's privacy settings
func UpdateSettings(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var settings Settings
	settings.UserID = ctx.Value(key("user")).(uint)
	// Apply any settings decoded from the body
	json.NewDecoder(r.Body).Decode(&settings)
	settings.update()
	// Fill in the rest of the struct for encoding purposes
	if err := settings.get(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	json.NewEncoder(w).Encode(settings)
}
