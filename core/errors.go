package core

import (
	"encoding/json"
	"fmt"
	"log"
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

func ServerErrorFrom(e error) HTTPError {
	return HTTPError{
		Title:   "Internal Server Error",
		Message: e.Error(),
		Status:  500}
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

// WriteError400 - Write a JSON formatted bad request error with msg to w
func WriteError400(w http.ResponseWriter, msg string) {
	WriteError(w, HTTPError{
		Title:   "Bad Request",
		Message: msg,
		Status:  400})
}

// WriteError500 - Write a JSON formatted internal server error based on error e to w
func WriteError500(w http.ResponseWriter, e error) {
	// Because these errors are at the server's fault, it is important to log their messages to gain an idea of where errors are frequently occuring
	log.Println(e)
	WriteError(w, ServerErrorFrom(e))
}

// WriteError404 - Write a JSON formatted 404 error to w
func WriteError404(w http.ResponseWriter) {
	WriteError(w, HTTPError{
		Title:   "Not Found",
		Message: "The requested resource was unable to be found",
		Status:  404})
}
