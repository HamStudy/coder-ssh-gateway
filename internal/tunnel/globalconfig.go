package tunnel

import (
	"errors"
	"os"
	"strings"
)

func EnsureGlobalConfigDir(path string) error {
	if strings.Contains(path, "/.config/") {
		return errors.New("global config path must not contain /.config/")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}
