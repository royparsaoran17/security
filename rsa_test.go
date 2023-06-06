package security

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()

	assert.NoError(t, err)
	assert.NotNil(t, privateKey)
	assert.NotNil(t, publicKey)

	fmt.Printf("TYPE PRIVATE KEY: %v\n", reflect.TypeOf(privateKey))
	fmt.Printf("TYPE PUBLIC KEY: %v\n", reflect.TypeOf(publicKey))
	fmt.Printf("PRIVATE KEY: %v\n", privateKey)
	fmt.Printf("PUBLIC KEY: %v\n", publicKey)
}

func TestGenerateKeyBytes(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyBytes()

	assert.NoError(t, err)
	assert.NotEmpty(t, privateKey)
	assert.NotEmpty(t, publicKey)

	fmt.Printf("PRIVATE KEY: %v\n", privateKey)
	fmt.Printf("PUBLIC KEY: %v\n", publicKey)
}

func TestGenerateKey64(t *testing.T) {
	priKeyPem, pubKeyPem, err := GenerateKey64()

	assert.NoError(t, err)
	assert.NotEmpty(t, priKeyPem)
	assert.NotEmpty(t, pubKeyPem)

	fmt.Println(priKeyPem)
	fmt.Println(pubKeyPem)
}

func TestGenerateSecretKey(t *testing.T) {
	key, err := GenerateSecretKey()

	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotEmpty(t, key.PrivateKey)
	assert.NotEmpty(t, key.PublicKey)

	fmt.Println(key.PrivateKey)
	fmt.Println(key.PublicKey)
}
