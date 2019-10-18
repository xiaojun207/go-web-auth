package web

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"
)

const (
	appkey    = "868e0c86ae5eaef4cab2124c4b9f953b"
	appSecret = "b0dcf3580fddfe02d5da423351f523c4"
)

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	ResultSuccess(w, "Gained access to protected resource")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user UserCredentials

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		ResultFail(w, "NewDecoder Error in request")
		return
	}

	if strings.ToLower(user.Username) != appkey && user.Password != appSecret {
		w.WriteHeader(http.StatusForbidden)
		fmt.Println("Error logging in")
		ResultFail(w, "Invalid credentials")
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 12).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims = claims

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResultFail(w, "Error extracting the key")
		fatal(err)
	}

	tokenString, err := token.SignedString([]byte(TokenSecretKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResultFail(w, "Error while signing the token")
		fatal(err)
	}

	response := Token{tokenString}
	ResultSuccess(w, response)

}
