package main

import (
	"os"

	"github.com/LunFengChen/xfinject/src"
)

func main() {
	os.Exit(xfinject.RunCLI(os.Args[1:]))
}
