//go:build !linux

package app

import "errors"

var errNoTTY = errors.New("no controlling terminal; use --stdin")

func readHiddenTTYLine() (string, error) { return "", errNoTTY }

func readTTYLine() (string, error) { return "", errNoTTY }
