package controller

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/leandrobove/fc-keycloak/api/authorization_code_flow/auth"
	"golang.org/x/oauth2"
)

var ctx = context.Background()

var state string
var codeVerifier string

type AuthController struct {
	config oauth2.Config
}

func NewAuthController(config oauth2.Config) *AuthController {
	return &AuthController{
		config: config,
	}
}

func (h AuthController) GetLoginRequest(c *gin.Context) {
	//generate state param
	state, _ = auth.GenerateOAuth2State()

	//generate code verifier
	codeVerifier, _ = auth.GenerateRandomCodeVerifier()

	//generate code challenge
	codeChallenge := auth.GenerateCodeChallenge(codeVerifier)

	codeChallengeParam := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodParam := oauth2.SetAuthURLParam("code_challenge_method", "S256")

	loginUrl := h.config.AuthCodeURL(state, codeChallengeParam, codeChallengeMethodParam)

	c.Redirect(http.StatusFound, loginUrl)
}

func (h AuthController) GetCallbackRequest(c *gin.Context) {
	errorParam := c.Request.URL.Query().Get("error")
	if errorParam != "" {
		log.Print("error: ", errorParam)
		c.Redirect(http.StatusFound, "/login")
		return
	}

	authCode := c.Request.URL.Query().Get("code")
	if authCode == "" {
		//redirect to login page
		log.Print("error: 'code' query param missing")
		c.Redirect(http.StatusFound, "/login")
		return
	}

	//check state value
	stateReturned := c.Request.URL.Query().Get("state")
	if stateReturned != state {
		//redirect to login page
		log.Print("error: 'state' query param missing")
		c.Redirect(http.StatusFound, "/login")
		return
	}

	//set code verifier param
	codeVerifierParam := oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	//exchange auth code for access token
	token, err := h.config.Exchange(ctx, authCode, codeVerifierParam)
	if err != nil {
		log.Print("error: ", err.Error())
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.PureJSON(http.StatusOK, token)
}
