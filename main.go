package main

import (
	"fmt"

	l "github.com/watts-kit/wattsPluginLib"
	//l "../wattsPluginLib"
)

const (
	authorizedKeyFile = "~/.ssh/authorized_keys"
)

func request(pi l.Input) l.Output {
	h := pi.SSHHostFromConf("user", "host")

	publicKey := pi.PublicKeyFromParams("pub_key")

	output, err := h.RunSSHCommandErr(
		"grep",
		fmt.Sprintf("'%s'", publicKey),
		authorizedKeyFile)
	if output != "" {
		l.PluginUserError(
			fmt.Sprint("err:", err, "output:", output),
			"This public key is already used")
	}

	h.RunSSHCommand("cp", authorizedKeyFile, authorizedKeyFile+".bak")

	uid := fmt.Sprintf("%s_%s", pi.Conf["prefix"], pi.WaTTSUserID)
	newLine := fmt.Sprintf("command=\\\"%s %s %s %s\\\",no-pty %s",
		pi.Conf["script_path"],
		uid,
		pi.Conf["myproxy_server"],
		pi.Conf["myproxy_server_pwd_key"],
		publicKey)

	h.RunSSHCommand("echo", newLine, ">>", authorizedKeyFile)

	credentials := []l.Credential{
		l.AutoCredential("retrieval host", fmt.Sprintf("%s@%s", pi.Conf["user"], pi.Conf["host"])),
	}

	// uid as state
	return l.PluginGoodRequest(credentials, uid)
}

func revoke(pi l.Input) l.Output {
	h := pi.SSHHostFromConf("user", "host")
	h.RunSSHCommand("sed", "-i.bak", "/"+pi.CredentialState+"/d", authorizedKeyFile)
	return l.PluginGoodRevoke()
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version: "1.0.0",
		Author:  "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		Actions: map[string]l.Action{
			"request": request,
			"revoke":  revoke,
		},
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "myproxy_server", Type: "string", Default: "master.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "script_path", Type: "string", Default: "./getCert"},
			l.ConfigParamsDescriptor{Name: "host", Type: "string", Default: "watts-x509.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "display_host", Type: "string", Default: "watts-x509.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "user", Type: "string", Default: "x509"},
			l.ConfigParamsDescriptor{Name: "prefix", Type: "string", Default: "foobar"},
		},
		RequestParams: []l.RequestParamsDescriptor{
			l.RequestParamsDescriptor{
				Key: "pub_key", Name: "public key", Description: "the public key of the service", Type: "textarea",
				Mandatory: true},
		},
	}
	l.PluginRun(pluginDescriptor)
}
