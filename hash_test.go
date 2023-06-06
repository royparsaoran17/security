package security

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHashMake(t *testing.T) {
	password := "Hell@Yeah"

	hash := HashMake(password)

	t.Run("it should not be empty", func(t *testing.T) {
		assert.NotEmpty(t, hash)
	})

	t.Run("it should not be equal", func(t *testing.T) {
		assert.NotEqual(t, password, hash)
	})

	verified := HashVerify(password, hash)

	t.Run("it should be valid verify", func(t *testing.T) {
		assert.True(t, verified)
	})

	password2 := "Hell@Yooo"

	verified2 := HashVerify(password2, hash)
	t.Run("it should invalid", func(t *testing.T) {
		assert.False(t, verified2)
	})
}
