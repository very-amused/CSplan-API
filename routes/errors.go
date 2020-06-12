package routes

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator"
)

// Error - Error to be sent to a client over HTTP
type Error struct {
	Title   string `json:"title"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func (e Error) Error() string {
	return e.Message
}

var validate *validator.Validate

func init() {
	validate = validator.New()
}

// HTTPError - Write a JSON formatted error to w
func HTTPError(w http.ResponseWriter, e Error) {
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(e)
}

// HTTPValidate - Validate struct s and write a JSON formatted error to w if validation fails
func HTTPValidate(w http.ResponseWriter, s interface{}) error {
	err := validate.Struct(s)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Validation Error",
			Message: err.Error(),
			Status:  400})
	}
	return err
}

// HTTPInternalServerError - Write a JSON formatted internal server error based on error e to w
func HTTPInternalServerError(w http.ResponseWriter, e error) {
	err := Error{
		Title:   "Intenal Server Error",
		Message: e.Error(),
		Status:  500}
	HTTPError(w, err)
}
