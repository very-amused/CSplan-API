package auth

import (
	"fmt"

	"github.com/very-amused/CSplan-API/core"
)

// HashParams - Parameters supplied to a hash function that derives the user's password into a key
type HashParams struct {
	Type     string  `json:"type"`
	SaltLen  *uint8  `json:"saltLen"`
	TimeCost *uint32 `json:"timeCost"`
	MemCost  *uint32 `json:"memCost"`
	Threads  *uint8  `json:"threads"`
}

// Argon2 max values
const argon2MaxTimeCost = 10
const argon2MaxMemCost = 2097152 // 2GiB
const argon2MaxThreads = 1       // Restrict to 1 thread

// Validate a set of HashParams
func (h HashParams) Validate() (err *core.HTTPError) {
	err = &core.HTTPError{
		Title:   "Validation Error",
		Message: "",
		Status:  400}
	switch h.Type {
	case "argon2i":
		// Make sure all needed parameters are supplied
		if h.TimeCost == nil ||
			h.MemCost == nil ||
			h.Threads == nil ||
			h.SaltLen == nil {
			err.Message = "Missing hash parameters (argon2i: t_cost, m_cost, parallelism)."
			return err
		}
		// Validate each parameter
		if *h.SaltLen > 16 {
			err.Message = "Invalid salt length (argon2i, max 16)."
			return err
		} else if *h.TimeCost < 1 || *h.TimeCost > argon2MaxTimeCost {
			err.Message = fmt.Sprintf("Invalid time cost (argon2i, 1-%d).", argon2MaxTimeCost)
			return err
		} else if *h.MemCost < 1 || *h.MemCost > argon2MaxMemCost {
			err.Message = fmt.Sprintf("Invalid memory cost (argon2i, 1-%d).", argon2MaxMemCost)
			return err
		} else if *h.Threads < 1 || *h.Threads > argon2MaxThreads {
			err.Message = fmt.Sprintf("Invalid parallelism (argon2i, 1-%d).", argon2MaxThreads)
			return err
		}
		break

	default:
		err.Message = "Invalid hash type."
		return err
	}

	// If err isn't returned at any point previously, validation was successful and nil can be returned
	return nil
}
