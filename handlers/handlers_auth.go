package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/abhiraj-ku/auth_in_go/models"
	"github.com/abhiraj-ku/auth_in_go/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis"
)

type Claims struct {
	Email  string    `json:"email"`
	UserId uuid.UUID `json:"userId"`
	jwt.StandardClaims
}

type JWTOutput struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type SessionData struct {
	Token  string `json:"token"`
	UserId string `json:"userId"`
}

func (lac *LocalApiConfig) SignInHandler(c *gin.Context) {

	var userToAuth models.UserToAuth

	// check if response is in json or not
	if err := c.ShouldBindJSON(&userToAuth); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// insert validation here
	validationErrors := utils.ValidateUserToAuth(userToAuth)
	if len(validationErrors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": validationErrors,
		})
		return
	}

	// fetch and check user's detail against saved data in DB
	foundUser, err := lac.DB.FindUserByEmail(c, userToAuth.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No user found ",
		})
		return
	}

	// check password validity
	if foundUser.Password != userToAuth.Password {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Password is invalid",
		})
		return

	}

	// define expiration time for jwt tokens

	expireTime := time.Now().Add(60 * time.Minute)
	// fill the claims struct
	claims := &Claims{
		Email:  userToAuth.Email,
		UserId: foundUser.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	sessionId := uuid.New().String()

	sessionData := map[string]interface{}{
		"token":  tokenString,
		"userId": foundUser.ID,
	}

	sessionDataJson, err := json.Marshal(sessionData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to encode session data into json format",
		})
		return
	}

	// set this data into redis also
	err = lac.RedisClient.Set(c, sessionId, sessionDataJson, time.Until(expireTime)).Err()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to save session data to redis",
		})
		return
	}

	// store this user who is online based on recently created session
	onlineUserData := map[string]interface{}{
		"username": foundUser.Name,
		"userId":   foundUser.ID,
	}

	onlineUserDataJson, err := json.Marshal(onlineUserData)

	// create key for saving data into redis
	onlineUserKey := "onlineUser:" + sessionId

	err = lac.RedisClient.Set(c, onlineUserKey, onlineUserDataJson, time.Until(expireTime)).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to mark user as online" + err.Error(),
		})
		return
	}

	// set the cookies
	c.SetCookie("session_id", sessionId, int(time.Until(expireTime).Seconds()), "/", "localhost", false, true)

	// send json data as response
	c.JSON(http.StatusOK, gin.H{
		"message": "Login success",
		"expires": expireTime,
		"token":   tokenString,
		"userId":  foundUser.ID,
	})

}

// logout functionality
func (lac *LocalApiConfig) LogoutHandler(c *gin.Context) {
	sessionID, err := c.Cookie("session_id")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized request",
		})
		return
	}

	err = lac.RedisClient.Del(c, sessionID).Err()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "failed to end session",
		})
		return
	}
	c.SetCookie("session_id", "", -1, "/", "", false, true)

	// remove online user key from redis
	onlineKey := "onlineUser:" + sessionID
	err = lac.RedisClient.Del(c, onlineKey).Err()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "failed to remove online user from redis" + err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out sucessfully",
	})

}

// Auth middleware
func (lac *LocalApiConfig) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized -no session",
			})
			return
		}
		SessionDataJSON, err := lac.RedisClient.Get(c, sessionID).Result()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired session",
			})
			return
		}
		var sessionData SessionData
		err = json.Unmarshal([]byte(SessionDataJSON), &sessionData)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Failed to decode the session data",
			})
			return
		}

		// token
		token, err := jwt.ParseWithClaims(sessionData.Token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			return
		}
		c.Set("userId", sessionData.UserId)
		c.Next()

	}
}

// sample function to check auth route working or not
func (lac *LocalApiConfig) HandlerAuthRoute(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Auth routes are working ",
	})
}

// Fetch online users
// we do this by first, fetching the keys , which indicates that a session
// is present which means there has be a user

func (lac *LocalApiConfig) HandlerFetchOnlineUsers(c *gin.Context) {
	// for prod we should user Scan() instead of keys because of performance issues
	keys, err := lac.RedisClient.Keys(c, "onlineUser:*").Result()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch keys from redis " + err.Error(),
		})
		return
	}

	if len(keys) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message":     "No online users found",
			"onlineUsers": nil,
		})
		return
	}

	// use redis pipeline to execute all query at once

	pipe := lac.RedisClient.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))

	for i, key := range keys {
		cmds[i] = pipe.Get(c, key)
	}
	_, err = pipe.Exec(c)
	if err != nil {
		panic(err)
	}

	// prepare a slice to store the users data
	onlineUsers := make([]map[string]interface{}, 0, len(keys))
	// get data result from the pipeline and populate this slice
	for _, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil {
			panic(err)
		}

		var userData map[string]interface{}

		err = json.Unmarshal([]byte(data), &userData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to unmarshal json data from redis" + err.Error(),
			})
			return
		}
		onlineUsers = append(onlineUsers, userData)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "ok",
		"onlineUser": onlineUsers,
	})

}

// Handle user password reset
func (lac *LocalApiConfig) HandlerPasswordReset(c *gin.Context) {
	var emailType models.EmailType

	if err := c.ShouldBindJSON(&emailType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to parse email type",
		})
		return
	}
	res, err := lac.HandlerSendEmail(emailType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to send email",
		})
		return
	}
	if res.StatusCode >= 300 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "email service responded with error" + res.Body,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset link sent successfully",
		"result":  res,
	})
}

// Kafka handler
