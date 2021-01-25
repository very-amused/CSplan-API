package core

// The existence of this file goes against golang's guidelines for declaring types separately from type usage,
// but these types are used across multiple different route handlers, so here they go

// State - information about the state of a resource
type State struct {
	Checksum string `json:"checksum"`
}

// IndexedState - Information about the state of an ordered resource
type IndexedState struct {
	Checksum string `json:"checksum"`
	Index    uint   `json:"index" db:"_Index"`
}

// Meta - Information about the state of a zero-access resource, needed to cache, decrypt, and update the resource clientside
type Meta struct {
	CryptoKey string `json:"cryptoKey" validate:"required,base64,max=700"`
	Checksum  string `json:"checksum"`
}

// IndexedMeta - Meta information with an index property added
type IndexedMeta struct {
	CryptoKey string `json:"cryptoKey"`
	Checksum  string `json:"checksum"`
	Index     uint   `json:"index"`
}

// MetaPatch - same as Meta, but with alloance for empty CryptoKeys, for use in PATCH requests
type MetaPatch struct {
	CryptoKey *string `json:"cryptoKey,omitempty" validate:"omitempty,base64,max=700"`
	Checksum  string  `json:"checksum"`
}

// StateResponse - Response containing only meta.checksum
type StateResponse struct {
	Meta State `json:"meta"`
}
