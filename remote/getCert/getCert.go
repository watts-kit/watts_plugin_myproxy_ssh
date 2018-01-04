package main

import (
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/exec"
	"strings"
    "github.com/watts-kit/passwordd/passwordclib"
)

const version = "0.1.0"

func main() {
	app := kingpin.New(
		"remotePlugin",
		"remote part of the wattsPluginMyproxySSH",
	)
	wattsUID := app.Arg("WaTTS User ID", "").Required().String()
	host := app.Arg("Host", "").Required().String()
	app.Author("Lukas Burgey")
	app.Version(version)

    password, pwdc_err := passwordclib.GetPassword("myproxy_server_pwd")
    if pwdc_err != nil {
        fmt.Printf ("error. You should add 'myproxy_server_pwd' to passwordd, for example with ----passwordc set myproxy_server_pwd-------- %s", pwdc_err)
        panic(pwdc_err)
    }
	kingpin.MustParse(app.Parse(os.Args[1:]))

	cmd := exec.Command("myproxy-logon", "-l", *wattsUID, "-s", *host, "-S", "-o", "-")
	cmd.Stdin = strings.NewReader(password)

	output, err := cmd.CombinedOutput()
	kingpin.FatalIfError(err, string(output))

	fmt.Println(string(output))
}
