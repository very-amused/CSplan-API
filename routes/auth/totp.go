package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/very-amused/CSplan-API/core"
)

var backupCodeMax = big.NewInt(99999999)

type TOTPInfo struct {
	UserID        uint     `json:"-"`
	Secret        []byte   `json:"-"`
	EncodedSecret string   `json:"secret,omitempty"`
	BackupCodes   []uint64 `json:"backupCodes"`
}

type TOTPRequest struct {
	Code *uint64 `json:"TOTP_Code"`
}

// Enable or disable TOTP (not used for updating TOTP secrets)
func SetTOTP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Parse action and pass to the appropriate subhandler
	action := r.URL.Query().Get("action")
	switch action {
	case "disable":
		disableTOTP(ctx, w, r)
		break

	case "enable":
		enableTOTP(ctx, w, r)
		break

	default:
		core.WriteError(w, core.HTTPError{
			Title:   "Invalid Action Parameter",
			Message: "To enable or disable TOTP, either ?action=enable or ?action=disable must be specified.",
			Status:  429})
	}
}

func GetBackupCodes(ctx context.Context, w http.ResponseWriter, _ *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)

	rows, err := core.DB.Query("SELECT BackupCodes FROM TOTP WHERE UserID = ?", userID)
	defer rows.Close()
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	if !rows.Next() {
		core.WriteError(w, core.HTTPError{
			Title:   "Precondition Failed",
			Message: "TOTP is not enabled for this user.",
			Status:  412})
		return
	}

	// No decoding and re-encoding is necessary because the backup codes are already stored as json
	var encodedBackupCodes []byte
	rows.Scan(&encodedBackupCodes)

	w.Write(encodedBackupCodes)
}

func validateTOTP(totp TOTPInfo, code uint64) (e *core.HTTPError) {
	// Create 30 second TOTP counter
	now := time.Now().Unix()
	counter := uint64(math.Floor(float64(now) / float64(30)))

	// Create a second counter 2s in the past, accounting for up to 2s of network delay
	backupCounter := uint64(math.Floor(float64(now-2) / float64(30)))

	if correct := RunTOTP(totp.Secret, counter); int32(code) == correct {
		return nil
	} else if correct := RunTOTP(totp.Secret, backupCounter); int32(code) == correct {
		return nil
	}

	// Test code against backup codes
	for i, backupCode := range totp.BackupCodes {
		if code == backupCode {
			// Invalidate (delete) the backup code
			newCodes := totp.BackupCodes
			newCodes = append(newCodes[0:i], newCodes[i+1:]...)
			encodedBackupCodes, _ := json.Marshal(newCodes)
			_, err := core.DB.Exec("UPDATE TOTP SET BackupCodes = ? WHERE UserID = ?", encodedBackupCodes, totp.UserID)
			if err != nil {
				serverErr := core.ServerErrorFrom(err)
				return &serverErr
			}
			return nil
		}
	}

	return &core.HTTPError{
		Title:   "Unauthorized",
		Message: "Invalid TOTP or backup code.",
		Status:  401}
}

func RunTOTP(secret []byte, counter uint64) (code int32) {
	// Encode counter as big endian binary
	binCounter := make([]byte, 8)
	binary.BigEndian.PutUint64(binCounter, counter)

	// Create and run HMAC
	mac := hmac.New(sha1.New, secret)
	mac.Write(binCounter)
	result := mac.Sum(nil)

	// Dynamic truncation as specified in RFC 4226
	offset := result[19] & 0xf
	return int32(
		(((int64(result[offset] & 0x7f)) << 24) |
			((int64(result[offset+1] & 0xff)) << 16) |
			((int64(result[offset+2] & 0xff)) << 8) |
			(int64(result[offset+3] & 0xff))) % int64(math.Pow10(6)))
}

func enableTOTP(ctx context.Context, w http.ResponseWriter, _ *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)

	// Don't overwrite existing TOTP settings
	rows, err := core.DB.Query("SELECT 1 FROM TOTP WHERE UserID = ?", userID)
	defer rows.Close()
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	if rows.Next() {
		core.WriteError(w, core.HTTPError{
			Title:   "Resource Conflict",
			Message: "TOTP is already enabled for this user.",
			Status:  409})
		return
	}

	var totp TOTPInfo
	// Generate a 20-byte TOTP secret per RFC 4226 recommendation
	totp.Secret = make([]byte, 20)
	rand.Read(totp.Secret)
	// Generate 10 8-digt backup codes
	totp.BackupCodes = make([]uint64, 10)
	for i := 0; i < 10; i++ {
		code, _ := rand.Int(rand.Reader, backupCodeMax)
		totp.BackupCodes[i] = code.Uint64()
	}

	// Insert TOTP info into db
	encodedBackupCodes, _ := json.Marshal(totp.BackupCodes)
	_, err = core.DB.Exec("INSERT INTO TOTP (UserID, _Secret, BackupCodes) VALUES (?, ?, ?)",
		userID, totp.Secret, encodedBackupCodes)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(201)
	// Encode secret as uppercase base32 per RFC 6238
	totp.EncodedSecret = strings.ToUpper(base32.StdEncoding.EncodeToString(totp.Secret))
	json.NewEncoder(w).Encode(totp)
}

func disableTOTP(ctx context.Context, w http.ResponseWriter, _ *http.Request) {
	userID := ctx.Value(core.Key("user")).(uint)
	core.DB.Exec("DELETE FROM TOTP WHERE UserID = ?", userID)
	w.WriteHeader(204)
}
