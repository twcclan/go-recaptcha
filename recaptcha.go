package recaptcha

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

const (
	Url = "https://www.google.com/recaptcha/api/siteverify"
)

var (
	ErrMissingInputSecret   = errors.New("The secret parameter is missing.")
	ErrInvalidInputSecret   = errors.New("The secret parameter is invalid or malformed.")
	ErrMissingInputResponse = errors.New("The response parameter is missing.")
	ErrInvalidInputResponse = errors.New("The response parameter is invalid or malformed.")
)

type Response struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Errors     []error  `json:"-"`
}

func (r *Response) getErrorFromCode(code string) error {
	switch code {
	case "missing-input-secret":
		return ErrMissingInputSecret
	case "invalid-input-secret":
		return ErrInvalidInputSecret
	case "missing-input-response":
		return ErrMissingInputResponse
	case "invalid-input-response":
		return ErrMissingInputResponse
	default:
		return nil
	}
}

func (r *Response) populateErrors() {
	for _, code := range r.ErrorCodes {
		r.Errors = append(r.Errors, r.getErrorFromCode(code))
	}
}

func Verify(secret string, response string, remoteip string) (*Response, error) {
	values := make(url.Values)
	values.Set("secret", secret)
	values.Set("response", response)

	resp, err := http.Get(Url + "?" + values.Encode())
	if err != nil {
		return nil, err

	}

	defer resp.Body.Close()

	recaptchaResponse := new(Response)

	err = json.NewDecoder(resp.Body).Decode(recaptchaResponse)
	if err != nil {
		return nil, err
	}

	recaptchaResponse.populateErrors()

	return recaptchaResponse, nil
}
