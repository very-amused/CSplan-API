package routes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"
)

// MakeID - Generate a uint ID of a specified number of digits
func MakeID(digits uint) (id uint, e error) {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		return 0, err
	}

	id = uint(binary.LittleEndian.Uint64(bytes))
	for math.Ceil(math.Log10(float64(id))) < float64(digits) {
		_, err := rand.Read(bytes)
		if err != nil {
			return 0, err
		}

		id += uint(binary.LittleEndian.Uint64(bytes))
	}
	final, err := strconv.ParseUint(strconv.Itoa(int(id))[0:digits], 10, 0)
	if err != nil {
		return 0, err
	}
	id = uint(final)

	return id, nil
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
	if err != nil {
		return 0, err
	}

	return uint(binary.LittleEndian.Uint64(bytes)), nil
}
