package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	core "github.com/very-amused/CSplan-API/core"
)

// Size in bytes of random IV passed to CTR cipher each time
const IVlen = 16

// Challenge - Encryption challenge to obtain authentication
type Challenge struct {
	ID          uint        `json:"-"`
	EncodedID   string      `json:"id"`
	Data        []byte      `json:"-"`
	EncodedData string      `json:"data" validate:"required"`
	Salt        string      `json:"salt"`
	HashParams  *HashParams `json:"hashParams,omitempty"`
}

type ChallengeRequest struct {
	User
	TOTPcode *uint64 `json:"TOTP_Code" validate:"required"`
}

func (challenge *Challenge) encryptData(block cipher.Block) error {
	// Generate an IV for the operation
	iv := make([]byte, IVlen)
	rand.Read(iv)

	// Create a CTR cipher
	ctr := cipher.NewCTR(block, iv)
	encrypted := make([]byte, len(challenge.Data))
	ctr.XORKeyStream(encrypted, challenge.Data)

	// Encode the encrypted data to send to the client
	challenge.EncodedData = base64.StdEncoding.EncodeToString(append(iv, encrypted...))
	return nil
}

// RequestChallenge - Request an authentication challenge
func RequestChallenge(_ context.Context, w http.ResponseWriter, r *http.Request) {
	// Enforce action verbage
	if r.URL.Query().Get("action") != "request" {
		core.WriteError(w, core.HTTPError{
			Title:   "Invalid Action Parameter",
			Message: "To enforce semantics, all new challenge requests must contain '?action=request'.",
			Status:  422})
		return
	}

	var user ChallengeRequest
	json.NewDecoder(r.Body).Decode(&user)

	if !user.exists() {
		core.WriteError(w, core.HTTPError{
			Title:   "Not Found",
			Message: "The user associated with the requested challenge does not exist.",
			Status:  404})
		return
	}
	// Get the user's ID
	core.DB.Get(&user.ID, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	// If the user has 2FA enabled, send a 412 (precondition failed), indicating that the client must submit a TOTP code along with the challenge request
	rows, err := core.DB.Query("SELECT _Secret, BackupCodes FROM TOTP WHERE UserID = ?", user.ID)
	defer rows.Close()
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	if rows.Next() {
		if user.TOTPcode == nil {
			core.WriteError(w, core.HTTPError{
				Title:   "Precondition Failed",
				Message: "TOTP code required to log in.",
				Status:  412})
			return
		}
		var totp TOTPInfo
		var encodedBackupCodes []byte
		rows.Scan(&totp.Secret, &encodedBackupCodes)
		json.Unmarshal(encodedBackupCodes, &totp.BackupCodes)
		totp.UserID = user.ID
		if httpErr := validateTOTP(totp, *user.TOTPcode); httpErr != nil {
			core.WriteError(w, *httpErr)
			return
		}
	}

	// If there are 5+ pending challenges for the user, or 10+ failed attempts decline providing a new one
	var pending uint
	var failed uint
	core.DB.Get(&pending, "SELECT COUNT(ID) FROM Challenges WHERE UserID = ? AND Failed = 0", user.ID)
	core.DB.Get(&failed, "SELECT COUNT(ID) FROM Challenges WHERE UserID = ? AND Failed = 1", user.ID)
	if pending >= 5 || failed >= 10 {
		core.WriteError(w, core.HTTPError{
			Title:   "Too Many Requests",
			Message: "There are too many pending/failed challenges requested to provide a new one. You are being ratelimited.",
			Status:  429})
		return
	}
	// Select and parse user's authentication key and hash parameters
	var challenge Challenge
	var saltAndKey []byte
	row := core.DB.QueryRow("SELECT AuthKey, HashParams FROM AuthKeys WHERE UserID = ?", user.ID)
	var encodedHashParams []byte
	err = row.Scan(&saltAndKey, &encodedHashParams)
	// Decode hash params
	challenge.HashParams = &HashParams{}
	json.Unmarshal(encodedHashParams, challenge.HashParams)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	// Slice salt and actual authKey using stored salt length (max 16)
	saltLen := *challenge.HashParams.SaltLen
	challenge.Salt = base64.StdEncoding.EncodeToString(saltAndKey[0:saltLen])
	authKey := saltAndKey[saltLen:]

	// Create a unique ID
	challenge.ID, err = core.MakeUniqueID("Challenges")
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	challenge.EncodedID = core.EncodeID(challenge.ID)

	// Generate 32 bytes of random data for the challenge
	challenge.Data = make([]byte, 32)
	rand.Read(challenge.Data)

	// Create a block cipher from the authkey, then encrypt the challenge's data
	block, err := aes.NewCipher(authKey)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	if err := challenge.encryptData(block); err != nil {
		core.WriteError500(w, err)
		return
	}

	// Add the challenge to the database
	_, err = core.DB.Exec("INSERT INTO Challenges (ID, UserID, _Data) VALUES (?, ?, ?)", challenge.ID, user.ID, challenge.Data)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	json.NewEncoder(w).Encode(challenge)
}

// SubmitChallenge - Submit an authentication challenge
func SubmitChallenge(_ context.Context, w http.ResponseWriter, r *http.Request) {
	// Enforce action verbage
	if r.URL.Query().Get("action") != "submit" {
		core.WriteError(w, core.HTTPError{
			Title:   "Invalid Action Parameter",
			Message: "To enforce semantics, all challenge submissions must contain '?action=submit'.",
			Status:  422})
		return
	}

	var challenge Challenge
	var user User
	json.NewDecoder(r.Body).Decode(&challenge)
	if err := core.ValidateStruct(challenge); err != nil {
		core.WriteError(w, *err)
		return
	}

	var err error
	challenge.ID, err = core.DecodeID(mux.Vars(r)["id"])
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Bad Request",
			Message: "Missing or malformed ID provided.",
			Status:  400})
		return
	}
	challenge.Data, err = base64.StdEncoding.DecodeString(challenge.EncodedData)

	var correctData []byte
	// The final clause checks that no challenges older than 1min are selected,
	// This accounts for the case where a partially unresponsive database must not allow a challenge to be attempted over and over again,
	// because of it not being set as failed or deleted
	row := core.DB.QueryRow("SELECT _Data, UserID FROM Challenges WHERE ID = ? AND Failed = 0 AND UNIX_TIMESTAMP() - _Timestamp <= 60", challenge.ID)
	err = row.Scan(&correctData, &user.ID)
	if err != nil {
		core.WriteError404(w)
		return
	}

	// Compare lengths first to avoid range errors
	if len(challenge.Data) != len(correctData) {
		core.DB.Exec("UPDATE Challenges SET Failed = 1 WHERE ID = ?", challenge.ID)
		core.WriteError(w, core.HTTPError{
			Title:   "Challenge Failed",
			Message: "Incorrect data provided.",
			Status:  401})
		return
	}

	// If the data isn't equal to the
	for i := range correctData {
		if correctData[i] != challenge.Data[i] {
			core.DB.Exec("UPDATE Challenges SET Failed = 1 WHERE ID = ?", challenge.ID)
			core.WriteError(w, core.HTTPError{
				Title:   "Challenge Failed",
				Message: "Incorrect data provided.",
				Status:  401})
			return
		}
	}

	// At this point, the challenge is successful and the user is authorized
	user.parseDeviceInfo(r)
	// Create new tokens
	core.DB.Exec("DELETE FROM Challenges WHERE ID = ?", challenge.ID)
	tokens, err := user.newSession()
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	user.EncodedID = core.EncodeID(user.ID)
	w.Header().Set("Set-Cookie", fmt.Sprintf("Authorization=%s; Path=/; HttpOnly; Max-Age=%d", tokens.Token, twoWeeks))
	json.NewEncoder(w).Encode(map[string]string{
		"id":        user.EncodedID,
		"CSRFtoken": tokens.CSRFtoken})
}
