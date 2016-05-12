/*
Application Security, Spring 2016

Passy: A simple terminal password manager
*/

package main

import ( 
	"crypto/rand"
	"crypto/aes"
  	"crypto/cipher"
  	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"io"
	"io/ioutil"
	"os"
	"flag"	
	"encoding/json"
	"fmt"	
	"errors"
	"bytes"
	"golang.org/x/crypto/scrypt"

)


const (
	KEY_SIZE   = 32  //AES-256 needs a 32-byte key
	SALT_SIZE  = 32
	MAC_SIZE = 32
	MAC_KEY_SIZE = 32
	NONCE_SIZE = 24
	AES_BLOCKSIZE = 16
	CIPHER_MODE_STRING_SIZE = 7
)

var (
	FILE_NAME = "box.txt"
	//cipher mode choices
	AES_CBC = []byte("aes_cbc")
	AES_CTR = []byte("aes_ctr")
	AES_ECB = []byte("aes_ecb")
)

//User can set cipher mode and can change it, ie: aes:cbc means aes with CBC
var CIPHER_MODE []byte

//when user enters password in we store it in memory as long as the program is running
//look into ways of maybe using hash of this and not keeping this in memory
var userPassPhase []byte

///////////
// Types
///////////

//Basic Type to hold a credential pair
type Credential struct{
		Username string
		Password []byte
}

//User holds a list of credentials in a map with key set as username for ease of discovery
type User struct{
	Bucket map[string]Credential
}


///////////
// Helpers
///////////

//getRandomBytes will return a buffer at given length with random data 
func getRandomBytes(length int) []byte{
	//allocate space with given length
	tmp := make([]byte, length)

	_, err := io.ReadFull(rand.Reader, tmp)

	if err != nil{
		tmp = nil
	}

	return tmp
}


// This is wrapper for generating a new random nonce.
func newNonce() *[NONCE_SIZE]byte {
	var nonce [NONCE_SIZE]byte
	tmp := getRandomBytes(NONCE_SIZE)
	if tmp == nil {
		return nil
	}
	copy(nonce[:], tmp)
	return &nonce
}

//given a buffer we must flush it so no trace of secrets are left behind for anyone who might come looking
//just xor the given byte with its self 
func flushBuffer(given []byte){
	for i := range given {
		given[i] ^= given[i]
	}
}

///////////
// Padding
///////////

//PKCS#5 padding will be used for block ciphers
//It takes the remaing byte length for next whole block and adds pad bytes with value of remaing
//https://www.socketloop.com/tutorials/golang-padding-un-padding-data

func padding(data []byte, blocksize int)[]byte {
	//get remaing bytes to fill to next whole block
	padding := blocksize - len(data)%blocksize
	paddedData := bytes.Repeat([]byte{byte(padding)}, padding)
	//add padding to data
	return append(data, paddedData...)
}

//take padded data and remove them
func removePadding(data []byte) []byte{
	length := len(data)
	toRemove := int(data[length-1])
	return data[:(length- toRemove)]
}

///////////
// Crypto
///////////

//HMAC SHA512
func calculateMAC(key, data []byte) (checksum []byte){
	hash := hmac.New(sha512.New, key)
	hash.Write(data)

	return hash.Sum(nil)
}

//check if mac is good for integrity
func verifyMAC(key, data, givenHMAC []byte) bool{
	acutal := calculateMAC(key, data)
	return subtle.ConstantTimeCompare(givenHMAC, acutal) == 1
}
//AES
		
///////////
//CTR MODE
//////////


//create a decrypt handler for CTR mode for aes256 with hmac-sha256
func decryptCTR(key, cipherText []byte) (plainText []byte, err error){
	//check key length
	if len(key) != KEY_SIZE{
		return nil, errors.New("encryption failed cause key does not match key length")
	}

	//check to see if ciphher text is not too short
	if len(cipherText) <= AES_BLOCKSIZE{
		fmt.Println("ciphertext is shorter than AES_BLOCKSIZE")
		return 
	}

	//setup a new cipher with given key
  	block, err := aes.NewCipher(key)

  	if err != nil {return}

  	//parseout init vec
  	initVec := cipherText[:AES_BLOCKSIZE]
  	//clean hmac out only initvec + message is left
  	cipherText = cipherText[AES_BLOCKSIZE:]

  	//new ctr
  	stream := cipher.NewCTR(block, initVec)

  	//make our plaintext with cipher text length
  	plainText = make([]byte, len(cipherText))
  	stream.XORKeyStream(plainText, cipherText)

  	return
}//fend

//create a encrypt handler for CTR mode for aes256 with hmac-sha256
func encryptCTR(key, plainText []byte) (cipherText []byte, err error){
	if len(key) != KEY_SIZE{
		return nil, errors.New("encryption failed cause key does not match key length")
	}

  	//setup a new cipher with given key
  	block, err := aes.NewCipher(key)

  	if err != nil{
    	panic(err)
  	}

  	//make our cipher and init with length of given plain text + aes block size
  	cipherText = make([]byte,len(plainText)+AES_BLOCKSIZE)

  	//random bytes but must be same as the block size
  	initVec := getRandomBytes(AES_BLOCKSIZE)
  	//new ctr
  	stream := cipher.NewCTR(block, initVec)

  	//set init vec bytes to ciphetext
  	for i := 0; i < AES_BLOCKSIZE; i++{
  		cipherText[i] = initVec[i]
  	}

  	//perform streaming xor
  	stream.XORKeyStream(cipherText[AES_BLOCKSIZE:], plainText)

  	//clean buffer
  	flushBuffer(initVec)

  	return 
}

////////////
//CBC MODE
///////////
func encryptCBC(key, plainText []byte) (cipherText []byte, err error){
  //must handel casses where plaintext size is not multiple of block size
  if len(plainText)%AES_BLOCKSIZE != 0{
    panic("plaintext is not a multiple of the block size")
  }

  //setup new aes cipher
  block, err := aes.NewCipher(key)
  if err != nil { panic(err) }

  cipherText = make([]byte, AES_BLOCKSIZE + len(plainText))
  //init our iv with random bytes
  initVec := getRandomBytes(AES_BLOCKSIZE)

  //setup a new encrypter
  mode := cipher.NewCBCEncrypter(block, initVec)

  //set init vec bytes to ciphetext
  for i := 0; i < AES_BLOCKSIZE; i++{
  	cipherText[i] = initVec[i]
  }

  mode.CryptBlocks(cipherText[AES_BLOCKSIZE:], plainText)

  return
}


func decryptCBC(key, cipherText []byte) (plainText []byte, err error){
  //setup a new cipher with given key
  block, err := aes.NewCipher(key)

  if err != nil {
		panic(err)
	}

  //ciphertext cant be less than givn blocksie
	if len(cipherText) < aes.BlockSize {
		panic("ciphertext too short")
	}

  //init our iv with random bytes
  initVec := cipherText[:AES_BLOCKSIZE]	
  //trim ciphertext from initvec
  cipherText = cipherText[AES_BLOCKSIZE:]

  //CBC only works with whole blocks
  if len(cipherText) % AES_BLOCKSIZE != 0{
    panic("ciphertext is not a multiple of the block size")
  }

  //setup a new decrypter
  mode := cipher.NewCBCDecrypter(block, initVec)
  //make our plaintext with cipher text length
  	plainText = make([]byte, len(cipherText))

  // CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plainText, cipherText)
	return
}


////////////
//ECB MODE
///////////
func encryptECB(key, plainText []byte) (cipherText []byte, err error){
	 //must handel casses where plaintext size is not multiple of block size
  if len(plainText)%AES_BLOCKSIZE != 0{
    panic("plaintext is not a multiple of the block size")
  }

  //setup new aes cipher
  block, err := aes.NewCipher(key)
  if err != nil { panic(err) }

  //create ciphertext slice set to 0, we will append as we enrypt blocks
  cipherText = make([]byte, 0)
  tmp := make([]byte, AES_BLOCKSIZE)

  for len(plainText) > 0{
  	 //setup a new encrypter
  	block.Encrypt(tmp, plainText)
  	//move one block up
  	plainText = plainText[AES_BLOCKSIZE:]
  	//append encrypted block to our cipherText
  	cipherText = append(cipherText, tmp...)
  }

  return
}

func decryptECB(key, cipherText []byte) (plainText []byte, err error){
	 //setup a new cipher with given key
  	block, err := aes.NewCipher(key)

  	if err != nil {
		panic(err)
	}

  	//ciphertext cant be less than givn blocksie
	if len(cipherText) < AES_BLOCKSIZE {
		panic("ciphertext too short")
	}

  	//ecb only works with whole blocks
  	if len(cipherText) % AES_BLOCKSIZE != 0{
   	 panic("ciphertext is not a multiple of the block size")
  	}

  	//ecb mode is basically no mode, as golang doesnt suport it directly we must do it ourseves
  	//make our plaintext to 0 bytes as we will append to it as we decrypt
  	plainText = make([]byte, 0)
  	tmp := make([]byte, AES_BLOCKSIZE)

  	for len(cipherText) > 0{
  		block.Decrypt(tmp, cipherText)
  		//move one block up
  		cipherText = cipherText[AES_BLOCKSIZE:]
  		//append decrypted block to our plaintext
  		plainText = append(plainText, tmp...)
  	}

  	return
}

//use scrypt key derivation function to generate a key to use for encryption
//takes a users passwrod 
//func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error)
//N is a CPU/memory cost parameter, which must be a power of two greater than 1. r and p must satisfy r * p < 2³⁰.

func getKey(password []byte, salt []byte) (key []byte) {
	
	//get key 
	key, err := scrypt.Key(password, salt, 1048576, 8, 1, KEY_SIZE)

	if err != nil{ 
		fmt.Println("scrypt error with getting key")
		return nil 
	}

	//flush out tmpKey used by scrypt
	//flushBuffer(tmpKey)
	//return back key
	return
}

//decryptFactory will decrypt the file that contains the stored info
func decryptFactory()(decryptedData []byte, err error){ 
	var data []byte
	data, err = ioutil.ReadFile(FILE_NAME)

	if err != nil{
		errors.New("==> Could not read data from file")
	}

	//parse out cipher mode 
	CIPHER_MODE = data[:CIPHER_MODE_STRING_SIZE]
	data = data[CIPHER_MODE_STRING_SIZE:]
	//parse out salt 
	salt := data[:SALT_SIZE]
	data = data[SALT_SIZE:]
	//parse out hmac
	checksum := data[:sha512.Size]
	data = data[sha512.Size:]
	
	//if user hasnt auth yet
	if userPassPhase == nil{
		userPassPhase, err = promtUserBytes("==> Please enter your master password: ")
		if err != nil {return}
	}

	//major key is the key to success
	majorKey := getKey(userPassPhase, salt)

	if majorKey == nil{
		err = errors.New("==> Could not generate key with Scrypt")
		return
	}

	//check HMAC
	if !verifyMAC(majorKey, data, checksum){
		fmt.Println("checksum does not match")
		return nil, err
	}

	if bytes.Equal(CIPHER_MODE, AES_CTR){
		decryptedData, err = decryptCTR(majorKey, data)

		if err != nil{
			fmt.Println(err)
			err = errors.New("==> Could not decrypt data")
		}

	}else if bytes.Equal(CIPHER_MODE, AES_CBC){
		
		decryptedData, err = decryptCBC(majorKey, data)
		//cbc needs padding operations to remove extra bytes
		decryptedData = removePadding(decryptedData)

		if err != nil{
			err = errors.New("==> Could not decrypt data")
		}
	}else if bytes.Equal(CIPHER_MODE, AES_ECB){
		decryptedData, err = decryptECB(majorKey, data)
		//ecb needs padding operations to remove extra bytes
		decryptedData = removePadding(decryptedData)

		if err != nil{
			err = errors.New("==> Could not decrypt data")
		}
	}

	return 
}

//encryptFactory will encrypt the given data to a file 
func encryptFactory(data []byte) (err error){ 

	//new salt bytes
	var salt []byte
	salt = getRandomBytes(SALT_SIZE)
	if salt == nil{
		err = errors.New("==> Could not generate new salt")
		return
	}
	
	//if user hasnt auth yet
	if userPassPhase == nil{
		userPassPhase, err = promtUserBytes("==> Please enter your master password: ")
		if err != nil {return}
	}

	//major key is the key to success
	majorKey := getKey(userPassPhase, salt)

	if majorKey == nil{
		err = errors.New("==> Could not generate key with Scrypt")
		return
	}
	
	var encryptedData []byte
	//Perform the acutal AES 256 bit encryption, the cipher mode will be chosen by the user 
	if bytes.Equal(CIPHER_MODE, AES_CTR){
		encryptedData, err = encryptCTR(majorKey, data)
		
		if err != nil{
			fmt.Println(err)
			err = errors.New("==> Could not encrypt data")
		}


	}else if bytes.Equal(CIPHER_MODE, AES_CBC){
		//cbc needs padding operations to fill to next whole block
		data = padding(data, AES_BLOCKSIZE)
		encryptedData, err = encryptCBC(majorKey, data)

		if err != nil{
			fmt.Println(err)
			err = errors.New("==> Could not encrypt data")
		}

	}else if bytes.Equal(CIPHER_MODE, AES_ECB){
		//cbc needs padding operations to fill to next whole block
		data = padding(data, AES_BLOCKSIZE)
		encryptedData, err = encryptECB(majorKey, data)

		if err != nil{
			fmt.Println(err)
			err = errors.New("==> Could not encrypt data")
		}
	}

	//compute and add HMAC for integrity reasons
	checksum := calculateMAC(majorKey, encryptedData)

	//concatenate the cipher mode, salt, HMAC and encrypted data to be written to file
	dataForFile := append(append(append(append([]byte{}, CIPHER_MODE...), salt...), checksum...), encryptedData...)


	//write encrypted info to file
	err = ioutil.WriteFile(FILE_NAME, dataForFile, 0600)

	if err != nil {
		err = errors.New("==> Could not write to file")
		fmt.Println("encryptFactory")
	}

	//take care of business
	flushBuffer(data)
	flushBuffer(majorKey)

	return 
}

/////////////////
// File Handlers
/////////////////

//openFile will decrypt and unmarhsal the box and return a user struct  
func openFile() User{
	data, err := decryptFactory()
	
	if err != nil{
		fmt.Println(err)
		fmt.Println("==> Faild to decrypt the storage file")
		//force quit
		os.Exit(1)
	}

	var user User
	//data stored in JSON so must read that into our user struct in memory
	err = json.Unmarshal(data, &user)
	if err != nil{
		fmt.Println(err)
		fmt.Println("==> Faild to Unmarshal JSON")
		os.Exit(1)
	}

	return user
}

//saveFile will take a user struct and marshal into JSON and then encrypt to file
func saveFile(user User){
	jsonify, err := json.Marshal(user)
	
	if err != nil{
		fmt.Println("==> Faild to marshal the user struct")
		os.Exit(1)
	}

	err = encryptFactory(jsonify)

	if err != nil{
		fmt.Println("==> Faild to encrypt and save file")
		os.Exit(1)
	}

}

//create a new box store with user password
func newBoxStore(){
	var newStore *os.File
	var err error
	newStore, err = os.Create("box.txt")

	if err != nil {
		panic("could not create new store")
	}
	newStore.Close()

	//create password for user and encrypt file
	//ask user for choice of cipher mode
	//tmp User to read data into memory
	var user = User{}
	//take care of business
	defer user.Flush()

	//tmp credential to store users new input
	var tmpCredential = Credential{}
	//take care of business
	defer tmpCredential.Flush()

	//if user hasnt auth yet
	if userPassPhase == nil{
		userPassPhase, err = promtUserBytes("==> Please enter your master password: ")
		if err != nil {return}
	}

	if CIPHER_MODE == nil{	
		for{
			userCipherChoice, _ := promptUserString("==> Please enter your cipher mode (aes_ecb, aes_cbc, aes_ctr): ")
			
			if (userCipherChoice == string(AES_CTR)){
				CIPHER_MODE = AES_CTR
				break
			}else if (userCipherChoice == string(AES_CBC)){
				CIPHER_MODE = AES_CBC
				break
			}else if (userCipherChoice == string(AES_ECB)){
				CIPHER_MODE = AES_ECB
				break
			}
		}

	}

	//set user admin credentials
	tmpCredential.Username = "ADMIN"
	tmpCredential.Password = userPassPhase
	user.Bucket = map[string]Credential{}
	user.Bucket["ADMIN"] = tmpCredential

	saveFile(user)
}


///////////
// Methods
///////////

//flush the bytes that stored the password for a given credential
func (c Credential) Flush(){
	//check if credential has been passed

	//flush bytes that store password
	flushBuffer(c.Password)
}

//User struct flush credential bucket
func (u User) Flush(){
	for i := range u.Bucket {
		u.Bucket[i].Flush()
	}
}

//pretty print a credential to console
func (c Credential) PrettyPrint () {
	fmt.Println("==> Username --> " + string(c.Username) + " Password --> " + string(c.Password))
}


//Ask user for a new credential pair and store to box
func newCredential(){
	//tmp User to read data into memory
	var user = User{}
	//take care of business
	defer user.Flush()

	//tmp credential to store users new input
	var tmpCredential = Credential{}
	//take care of business
	defer tmpCredential.Flush()

	//ask user for input
	fmt.Println("==> Please enter the credentials you would like to store. Two part process.")
	name, err := promptUser("==> Username: ")

	if err != nil{
		fmt.Println("==> Error in terminal")
		return
	} else if name == ""{
		fmt.Println("No username was entered, terminating...")
		return
	}

	//set name
	tmpCredential.Username = name

	password, err := promtUserBytes("==> Password: ")
	//clean up bytes
	defer flushBuffer(password)

	if err != nil{
		fmt.Println("==> Error in terminal")
		return
	}else if password == nil{
		fmt.Println("==>No password was entered, terminating...")
		return
	}

	//set password
	tmpCredential.Password = password

	//read data file into user struct in memory 
	user = openFile()
	//set credenital into user credential bucket and username as key for fast lookup
	user.Bucket[name] = tmpCredential
	//save user data strucutre into file after we are done
	saveFile(user)
	fmt.Println("==> New Credential has been stored")
}

//given a username if exits will return the password to the user
func retrievePassword(){
	//tmp User to read data into memory
	var user = User{}
	//take care of business
	defer user.Flush()

	//ask user for input
	fmt.Println("==> Please enter the username you want to retrieve password for")
	name, err := promptUser("==> Username: ")

	//chekc errors
	if err != nil{
		fmt.Println("==> Error in terminal")
		return
	} else if name == ""{
		fmt.Println("No username was entered, terminating...")
		return
	}

	//read data file into user struct in memory 
	user = openFile()

	//get the credtials for the given username 
	tmp, ok := user.Bucket[name]

	if !ok{
		fmt.Println("==> The username that you have given does not exist...")
		return
	}

	tmp.PrettyPrint()
}

//given a username if exits will return the password to the user
func matchCredentials(){
	fmt.Println("==> Please enter a username and password to check if it matchs record")
	//tmp User to read data into memory
	var user = User{}
	//take care of business
	defer user.Flush()

	//ask user for input
	fmt.Println("==> Please enter the username")
	name, err := promptUser("==> Username: ")

	//chekc errors
	if err != nil{
		fmt.Println("==> Error in terminal")
		return
	} else if name == ""{
		fmt.Println("No username was entered, terminating...")
		return
	}

	password, err := promtUserBytes("==> Password: ")
	//clean up bytes
	defer flushBuffer(password)

	if err != nil{
		fmt.Println("==> Error in terminal")
		return
	}else if password == nil{
		fmt.Println("==>No password was entered, terminating...")
		return
	}

	//read data file into user struct in memory 
	user = openFile()

	//get the credtials for the given username 
	tmp, ok := user.Bucket[name]

	if !ok{
		fmt.Println("==> The username that you have given does not exist...")
		return
	}

	if bytes.Equal(tmp.Password, password){
		fmt.Println("==> The given credentials are a match =)")
		return
	}else{
		fmt.Println("==> The password that you have given does not match given username...")
		return
	}

}	

// user can change cipher mode used, will have to decrypt and encrypt again
func changeCipherMode(){
	fmt.Println("==> Please enter a username and password to check if it matchs record")
	//tmp User to read data into memory
	var user = User{}
	//take care of business
	defer user.Flush()

	//read data file into user struct in memory 
	user = openFile()

	//set cipher mode to nill
	CIPHER_MODE = nil
	if CIPHER_MODE == nil{	
		for{
			userCipherChoice, _ := promptUserString("==> Please enter your cipher mode (aes_ecb, aes_cbc, aes_ctr): ")
			
			if (userCipherChoice == string(AES_CTR)){
				CIPHER_MODE = AES_CTR
				break
			}else if (userCipherChoice == string(AES_CBC)){
				CIPHER_MODE = AES_CBC
				break
			}else if (userCipherChoice == string(AES_ECB)){
				CIPHER_MODE = AES_ECB
				break
			}
		}
	}

	//save user data strucutre into file after we are done
	saveFile(user)
	fmt.Println("==> Cipher mode has been changed")

}

///////////////////
// Terminal Prompt
///////////////////
//https://github.com/gokyle/readpass/

func promptUser(promt string) (response string, err error){
	fmt.Printf(promt)
	_, err = fmt.Scanln(&response)
	if err != nil {
		panic(err)
	}
	return 
}


func promptUserString(promt string) (result string, err error){
	return promptUser(promt)
}

func promtUserBytes(promt string) (result []byte, err error){
	passwordAsString, err := promptUser(promt)

	if err == nil{
		result = []byte(passwordAsString)
	}
	return
}

///////////
// Main
///////////

func main(){
	if _, err := os.Stat("box.txt"); os.IsNotExist(err) {
		// no such file or dir
    	fmt.Println("No file box in path, will create new one for you...")

    	newBoxStore()
    	fmt.Println("New box has been created for you with given password, please run again to add new account")
    	os.Exit(1)
	}

	newPair := flag.Bool("new", false, "Create a Credential")
	retrieve := flag.Bool("get", false, "Get the password for a given ")
	mode := flag.Bool("mode", false, "Choose Cipher mode,  ECB, CTR or CBC")
	match := flag.Bool("match", false, "Given a username and password, check if valid")
	//parse command line arguments
	flag.Parse()

	//setup flag functionality 

	if *newPair {
		newCredential()
		return
	} else if *retrieve{
		retrievePassword()
		return
	} else if *mode{
		//ask user to change the cipher mode used for encryption
		changeCipherMode()
		return
	} else if *match{
		matchCredentials()
		return
	}
}

