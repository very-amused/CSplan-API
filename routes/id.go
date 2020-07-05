package routes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
)

// MakeID - Generate a uint ID of a specified number of digits
func MakeID() (id uint) {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return uint(binary.LittleEndian.Uint64(bytes))
}

// EncodeID - Encode a uint ID as a base64 string
func EncodeID(id uint) (encoded string) {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(id))
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// DecodeID - Decode a base64 string as an ID
func DecodeID(encoded string) (id uint, e error) {
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	return uint(binary.LittleEndian.Uint64(bytes)), err
}
