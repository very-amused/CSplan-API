package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
	if len(bytes) < 8 {
		bytes = make([]byte, 8) // Ensure there's enough bytes to not choke on Uint64 conversion
	}
	return uint(binary.LittleEndian.Uint64(bytes)), err
}

// MakeUniqueID - Return an ID that is unique at the time of calling, and any database related errors
// DO NOT CALL THIS WITH USER PROVIDED DATA, THE PROVIDED TABLE NAME IS INTERPOLATED INTO A QUERY WITH NO ESCAPING
func MakeUniqueID(tableName string) (id uint, e error) {
	id = MakeID()
	for {
		rows, e := DB.Query(fmt.Sprintf("SELECT 1 FROM %s WHERE ID = ?", tableName), id)
		if rows == nil {
			panic(fmt.Sprintf("MakeUniqueID call returned nil rows, it is likely the table '%s' doesn't exist.", tableName))
		}
		defer rows.Close()
		if rows == nil || !rows.Next() {
			return id, nil
		} else if e != nil {
			return id, e
		} else {
			id++
		}
	}
}
