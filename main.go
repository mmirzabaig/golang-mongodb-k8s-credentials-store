package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var tempUri = os.Getenv("MONGODB_URI")
var uri = "mongodb://" + tempUri + ":27017/?timeoutMS=5000"

// "mongodb+srv://mmirzabaig:Drinkwater65@cluster0.u6llroj.mongodb.net/?retryWrites=true&w=majority"
// "mongodb://10.0.2.15:27017/?timeoutMS=5000"

var mongoUser, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
var collection = mongoUser.Database("credentials-store").Collection("credentials")
var router = gin.Default()

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

// This should be in an env file in production
const MySecret string = "abc&1*~#^2^#s0^=)^^7%b34"

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

type User struct {
	Username string
	Secret   string
}
type RetrieveUser struct {
	Username string
}

// curl -X POST http://localhost:6680/addUser -H 'Content-Type: application/json' -d '{"username": "mmirzabaig", "secret": "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"}'
func addUser(c *gin.Context) {

	var postRequestUser User
	if err := c.BindJSON(&postRequestUser); err != nil {
		return
	}

	var retrieveUserResult User
	var retrieve RetrieveUser
	retrieve.Username = postRequestUser.Username

	collection.FindOne(context.TODO(), retrieve).Decode(&retrieveUserResult)
	json.Marshal(retrieveUserResult)

	if len(retrieveUserResult.Username) == 0 {

		encText, err := Encrypt(postRequestUser.Secret, MySecret)
		if err != nil {
			fmt.Println("error encrypting your classified text: ", err)
		}

		postRequestUser.Secret = encText

		result, err := collection.InsertOne(context.TODO(), postRequestUser)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("Inserted document with _id: %v\n", result.InsertedID)

		c.IndentedJSON(http.StatusCreated, result)
	} else {
		c.IndentedJSON(http.StatusCreated, "User "+retrieve.Username+" already is registerd")
	}

}

// curl -X POST http://localhost:6680/retrieveUser -H 'Content-Type: application/json' -d '{"username": "testing"}'
func retrieveUser(c *gin.Context) {

	var retrieve RetrieveUser

	if err := c.BindJSON(&retrieve); err != nil {
		return
	}

	var result User

	collection.FindOne(context.TODO(), retrieve).Decode(&result)
	json.Marshal(result)
	fmt.Println(result)
	if len(result.Username) != 0 {

		decText, err := Decrypt(result.Secret, MySecret)
		if err != nil {
			fmt.Println("error decrypting your encrypted text: ", err)
		}
		result.Secret = decText
		c.IndentedJSON(http.StatusCreated, result.Secret)
	} else {
		c.IndentedJSON(http.StatusCreated, "User "+retrieve.Username+" does not exist :(")
	}
}

func homePage(c *gin.Context) {

	fmt.Println("Hello! Homepage-- /")
	greeting := "Welcome to the credentials store"

	c.IndentedJSON(http.StatusCreated, greeting)
}

func main() {
	fmt.Println("hello")

	mongoUser, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = mongoUser.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()
	// Ping the primary
	if err := mongoUser.Ping(context.TODO(), readpref.Primary()); err != nil {
		panic(err)
	}
	fmt.Println("Successfully connected and pinged.")
	// -----------------------------------------------------------------------------------

	router.GET("/", homePage)
	router.POST("/addUser", addUser)
	router.POST("/retrieveUser", retrieveUser)

	fmt.Println("You are live on port 6680")
	router.Run(":6680")
}
