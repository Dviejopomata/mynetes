package utils

import "path/filepath"

func GetSshDirectory() string {
	sshPkDir, err := filepath.Abs("./storage")
	if err != nil {
		panic(err)
	}
	return sshPkDir
}
