package core

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator"
)

// HTTPError - Error to be sent as JSON over HTTP
type HTTPError struct {
	Title   string `json:"title"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("%s (status %d)", e.Message, e.Status)
}

var validate *validator.Validate

func init() {
	validate = validator.New()
}

// WriteError - Write a JSON formatted error to w
func WriteError(w http.ResponseWriter, e HTTPError) {
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(e)
}

// ValidateStruct - Validate struct s and write a JSON formatted error to w if validation fails
func ValidateStruct(s interface{}) *HTTPError {
	err := validate.Struct(s)
	if err != nil {
		return &HTTPError{
			Title:   "Validation Error",
			Message: err.Error(),
			Status:  400}
	}
	return nil
}

// WriteError500 - Write a JSON formatted internal server error based on error e to w
func WriteError500(w http.ResponseWriter, e error) {
	WriteError(w, HTTPError{
		Title:   "Internal Server Error",
		Message: e.Error(),
		Status:  500})
}

// WriteError404 - Write a JSON formatted 404 error to w
func WriteError404(w http.ResponseWriter) {
	WriteError(w, HTTPError{
		Title:   "Not Found",
		Message: "The requested resource was unable to be found",
		Status:  404})
}