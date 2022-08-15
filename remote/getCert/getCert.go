package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/watts-kit/passwordd/passwordclib"
	"gopkg.in/alecthomas/kingpin.v2"
)

const version = "0.1.0"

func main() {
	app := kingpin.New(
		"remotePlugin",
		"remote part of the wattsPluginMyproxySSH",
	)
	wattsUID := app.Arg("WaTTS User ID", "").Required().String()
	host := app.Arg("Host", "").Required().String()
	pwdKey := app.Arg("Password Key", "").Required().String()
	app.Author("Lukas Burgey")
	app.Version(version)

	//password, pwdc_err := passwordclib.GetPassword("myproxy_server_pwd")
	password, pwdcErr := passwordclib.GetPassword(*pwdKey)
	if pwdcErr != nil {
		fmt.Printf("error. The WaTTS admin should add 'myproxy_server_pwd' to passwordd %s", pwdcErr)
		panic(pwdcErr)
	}
	kingpin.MustParse(app.Parse(os.Args[1:]))

	cmd := exec.Command("myproxy-logon", "-l", *wattsUID, "-s", *host, "-S", "-o", "-")
	//myproxy-logon -l marcus -s watts-myproxy.lifescienceid.org -S-o -
	cmd.Stdin = strings.NewReader(password)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.EqualFold(string(output)[:30], "Failed to receive credentials.") {
			fmt.Println("\n\nNo credentials available for you.\nGenerate some using https://watts.lifescienceid.org\n\n")
		} else {
			kingpin.FatalIfError(err, string(output))
		}
	} else {
		fmt.Println(string(output))
	}
}
