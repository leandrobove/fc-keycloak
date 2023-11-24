package main

import (
	"github.com/gin-gonic/gin"
	"github.com/leandrobove/fc-keycloak/api/authorization_code_flow/controller"
	"golang.org/x/oauth2"
)

const (
	REALM               = ""
	AUTH_SERVER_BASEURL = "http://localhost:8080"
	AUTH_URL            = AUTH_SERVER_BASEURL + "/realms/" + REALM + "/protocol/openid-connect/auth"
	TOKEN_URL           = AUTH_SERVER_BASEURL + "/realms/" + REALM + "/protocol/openid-connect/token"
	CLIENT_ID           = ""
	CLIENT_SECRET       = ""
	CLIENT_REDIRECT_URI = "http://localhost:8081/callback"
)

func main() {
	endpoint := oauth2.Endpoint{
		AuthURL:  AUTH_URL,
		TokenURL: TOKEN_URL,
	}

	config := oauth2.Config{
		ClientID:     CLIENT_ID,
		ClientSecret: CLIENT_SECRET,
		Endpoint:     endpoint,
		RedirectURL:  CLIENT_REDIRECT_URI,
	}

	authController := controller.NewAuthController(config)

	r := gin.Default()
	//routes
	r.GET("/login", authController.GetLoginRequest)
	r.GET("/callback", authController.GetCallbackRequest)

	r.Run("localhost:8081")
}
