package main

import (
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/exec"
	"strings"
)

const version = "0.1.0"

func main() {
	app := kingpin.New(
		"remotePlugin",
		"remote part of the wattsPluginMyproxySSH",
	)
	wattsUID := app.Arg("WaTTS User ID", "").Required().String()
	host := app.Arg("Host", "").Required().String()
	password := app.Arg("Password", "").Required().String()
	app.Author("Lukas Burgey")
	app.Version(version)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	cmd := exec.Command("myproxy-logon", "-l", *wattsUID, "-s", *host, "-S", "-o", "-")
	cmd.Stdin = strings.NewReader(*password)

	output, err := cmd.CombinedOutput()
	kingpin.FatalIfError(err, string(output))

	fmt.Println(string(output))
}
