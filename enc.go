package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	m "math/rand"
	"net/http"
	"strings"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[m.Intn(len(letters))]
	}
	return string(b)
}

type FileEncDec struct {
	Key  []byte
	Path string
	Name string
	Mime string
}

func NewFileEncDec(path, name, key string) *FileEncDec {
	return &FileEncDec{Path: path, Name: strings.Trim(name, "/"), Key: []byte(key), Mime: Mime(name)}
}

func (fed *FileEncDec) DecB64(bytes []byte) ([]byte, error) {
	// Get image header
	decParts := strings.Split(string(bytes), ";base64,")
	//header := decParts[0]

	base64Text := make([]byte, b64.StdEncoding.DecodedLen(len(decParts[1])))
	l, err := b64.StdEncoding.Decode(base64Text, []byte(decParts[1]))
	if err != nil {
		return nil, err
	}

	return base64Text[:l], nil
}

func (fed *FileEncDec) EncB64(bytes []byte) []byte {
	e64 := b64.StdEncoding

	maxEncLen := e64.EncodedLen(len(bytes))
	encBuf := make([]byte, maxEncLen)

	e64.Encode(encBuf, bytes)
	return encBuf
}

func Mime(name string) string {
	if strings.HasSuffix(name, "png") {
		return "png"
	}
	if strings.HasSuffix(name, "jpg") {
		return "jpg"
	}
	if strings.HasSuffix(name, "jpeg") {
		return "jpeg"
	}
	if strings.HasSuffix(name, "gif") {
		return "gif"
	}
	if strings.HasSuffix(name, "webp") {
		return "webp"
	}
	if strings.HasSuffix(name, "ico") {
		return "ico"
	}
	return "unknown"
}

func (fed *FileEncDec) Header() string {
	return "name:" + fed.Name + ";data:image/" + fed.Mime + ";base64,"
}

func (fed *FileEncDec) LoadDecrypted() ([]byte, error) {
	file, err := ioutil.ReadFile(fed.FileName())
	if err != nil {
		return nil, err
	}

	return fed.EncB64(file), nil
}

func (fed *FileEncDec) LoadEncrypted() ([]byte, error) {
	// Read file
	enc_name := fed.FileName() + ".enc"
	file, err := ioutil.ReadFile(enc_name)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (fed *FileEncDec) FileName() string {
	return fed.Path + "/" + fed.Name
}

func (fed *FileEncDec) Writer(data []byte) {
	// Write file
	enc_name := fed.FileName() + ".enc"
	err := ioutil.WriteFile(enc_name, data, 0644)
	if err != nil {
		panic(err)
	}
}

func encrypt(key []byte, text string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text)) //b
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text)) //b
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)

	return text, nil
}

func main() {
	http.HandleFunc("/e/", serveImageEncrypt)
	http.HandleFunc("/d/", serveImageDecrypt)

	log.Println("Listening...")
	http.ListenAndServe(":3001", nil)
}

func serveImageEncrypt(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := strings.Trim(r.URL.Path, "/e")
	log.Println("[Serving] ", path)
	log.Println("encrypting")

	var fed = NewFileEncDec("./img", path, "h9h2fhfUVuS9jZ8uVbhV3vC5AWX39IVU")

	// Encrypt file
	b64, err := fed.LoadDecrypted()
	if err != nil {
		log.Println("ERROR loading:\n", err)
		return
	}

	// Apply Header
	hb64 := fed.Header() + string(b64)

	// Encrypt
	encrypted, err := encrypt(fed.Key, hb64)
	if err != nil {
		log.Println("ERROR encrypted:\n", err)
		return
	}

	// Write blob
	fed.Writer(encrypted)

	rw.Header().Set("Content-Type", "text/html")
	fmt.Fprint(rw, "Done: ", len(encrypted), " bytes")
	elapsed := time.Since(start)
	log.Printf("Served in %s", elapsed)
	return
}

func serveImageDecrypt(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := strings.Trim(r.URL.Path, "/d")
	log.Println("[Serving] ", path)
	log.Println("decrypting")

	var fed = NewFileEncDec("./img", path, "h9h2fhfUVuS9jZ8uVbhV3vC5AWX39IVU")

	// Decrypt file
	data, err := fed.LoadEncrypted()
	if err != nil {
		log.Fatalln("ERROR data:\n", err)
		return
	}

	decrypted, err := decrypt(fed.Key, data)
	if err != nil {
		log.Fatalln("ERROR decrypted:\n", err)
		return
	}

	decoded, err := fed.DecB64(decrypted)
	if err != nil {
		log.Fatalln("ERROR decoded:\n", err)
		return
	}

	rw.Header().Set("Content-Type", "image/"+fed.Mime)
	rw.Write(decoded)
	elapsed := time.Since(start)
	log.Printf("Served in %s", elapsed)
	return
}
