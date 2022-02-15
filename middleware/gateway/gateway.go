package gateway

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type MiddlewareHandler struct {
	ctx    context.Context
	Client *http.Client
	Name   string
	Roles  []float64
	Config Config
}

type ResponseError struct {
	Status interface{} `json:"status"`
}

type Status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// PayloadAuth define your jwt claim
type PayloadAuth struct {
	PersonalUserId float64
	RoleId         float64
}

type Config struct {
	JwtSecretKey  string
	ClientTimeout time.Duration
}

// Public Path for RS256
const (
	pubKeyPath = "public.pem"
)

var (
	verifyKey *rsa.PublicKey
	authData  *PayloadAuth
)

func init() {
	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
}

func (h *MiddlewareHandler) getHeaderToken(r *http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")
	index := 1
	if len(splitToken) > index {
		return splitToken[index], nil
	}
	return "", errors.New("invalid token")
}

func (h *MiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token, err := h.getHeaderToken(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Status: Status{
				Code:    http.StatusUnauthorized,
				Message: "Token Not Found",
			},
		})
		return
	}

	tokenParse, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	switch err.(type) {
	case nil: // no error
		if !tokenParse.Valid { // but may still be invalid
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(&ResponseError{
				Status: Status{
					Code:    http.StatusUnauthorized,
					Message: "Invalid Token",
				},
			})
			return
		}
	case *jwt.ValidationError: // something was wrong during the validation
		vErr := err.(*jwt.ValidationError)

		switch vErr.Errors {
		case jwt.ValidationErrorExpired:
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(&ResponseError{
				Status: Status{
					Code:    http.StatusUnauthorized,
					Message: "Token Expired",
				},
			})
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(&ResponseError{
				Status: Status{
					Code:    http.StatusInternalServerError,
					Message: "Error While Parsing Token",
				},
			})
			return
		}

	default: // something else went wrong
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Status: Status{
				Code:    http.StatusInternalServerError,
				Message: "Error While Parsing Token",
			},
		})
		return
	}

	if claims, ok := tokenParse.Claims.(jwt.MapClaims); ok && tokenParse.Valid {
		roleId := claims["roleId"].(float64)

		check := h.checkRole(roleId)
		if !check {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(&ResponseError{
				Status: Status{
					Code:    http.StatusForbidden,
					Message: "Forbidden",
				},
			})
			return
		}

		authData = &PayloadAuth{
			PersonalUserId: claims["sub"].(float64),
			RoleId:         roleId,
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Status: Status{
				Code:    http.StatusForbidden,
				Message: "Forbidden",
			},
		})
		return
	}

	req, err := http.NewRequestWithContext(h.ctx, r.Method, fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path), r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Status: Status{
				Code:    http.StatusInternalServerError,
				Message: "Internal Server Error",
			},
		})
		return
	}

	for key, value := range r.Header {
		req.Header[key] = value
	}

	// if you want to set header before call your service
	req.Header.Set("X-USER-ID", strconv.Itoa(int(authData.PersonalUserId)))
	req.Header.Set("X-USER-ROLE", strconv.Itoa(int(authData.RoleId)))

	req.URL.RawQuery = r.URL.RawQuery

	resp, err := h.Client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&ResponseError{
			Status: Status{
				Code:    http.StatusInternalServerError,
				Message: "Internal Server Error",
			},
		})
	} else {
		for key, value := range resp.Header {
			w.Header()[key] = value
		}
		w.WriteHeader(resp.StatusCode)

		_, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Println("failed to write response:", err.Error())
		}
	}
}

func (h *MiddlewareHandler) checkRole(rolesClaim float64) bool {
	for _, v := range h.Roles {
		if v == rolesClaim {
			return true
		}
	}
	return false
}

func New(ctx context.Context, name string, roles []float64, cfg Config) (http.Handler, error) {
	handler := MiddlewareHandler{
		ctx: ctx,
		Client: &http.Client{
			Timeout: cfg.ClientTimeout,
		},
		Name:   name,
		Roles:  roles,
		Config: cfg,
	}
	mux := http.NewServeMux()
	mux.Handle("/", &handler)
	return mux, nil
}
