package web

import (
	"encoding/json"
	"github.com/codegangsta/negroni"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"log"
	"net/http"
	"strconv"
)

const (
	TokenSecretKey = "2d621855115703d54a791ec9dfa8a5e0"
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data interface{} `json:"data"`
	Msg  string      `json:"msg"`
	Code string      `json:"code"`
}

type Token struct {
	Token string `json:"token"`
}

func StartServer(port int) {

	http.HandleFunc("/login", LoginHandler)

	http.Handle("/resource", negroni.New(
		negroni.HandlerFunc(ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(ProtectedHandler)),
	))

	log.Println("Now listening ", port, " ...")
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

func ValidateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(TokenSecretKey), nil
		})

	if err == nil {
		if token.Valid {
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			ResultFail(w, "Token is not valid")
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		ResultFail(w, "Unauthorized access to this resource")
	}

}

func ResultSuccess(w http.ResponseWriter, data interface{}) {
	response := Response{Data: data, Msg: "SUCCESS", Code: "200"}
	JsonResponse(response, w)
}

func ResultFail(w http.ResponseWriter, msg string) {
	response := Response{Msg: msg, Code: "400"}
	JsonResponse(response, w)
}

func JsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}
