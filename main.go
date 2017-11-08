package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"github.com/kalaspuffar/base64url"
	"os/exec"
	"strings"
)

func request(pi l.Input) l.Output {

	credential := []l.Credential{}
	var publicKey string

	// if the user has provided a public key we use it instead of generating a key pair
	if pk, ok := pi.Params["pub_key"]; ok {
		rawPublicKey, ok := pk.(string)
		l.CheckOk(ok, 1, "pub_key is no string")

		// parse the public key
		keyElements := strings.Split(rawPublicKey, " ")
		switch len(keyElements) {
		case 2:
			// case key-type + key
			publicKey = rawPublicKey
		case 3:
			// case key-type + key + comment
			publicKey = fmt.Sprintf("%s %s", keyElements[0], keyElements[1])
		default:
			l.PluginUserError(
				fmt.Sprintf("Cannot parse user provided public key (e = %v)", len(keyElements)),
				"Unable to parse the provided ssh public key",
			)
		}
	}

	credential = append(
		credential,
		l.AutoCredential("retrieval host", fmt.Sprintf("%s@%s",
			pi.Conf["user"],
			pi.Conf["host"])))

	// prepare parameters for the ssh command
	sshComment := fmt.Sprintf("%s_%s", pi.Conf["prefix"], pi.WaTTSUserID)
	linePrefix := fmt.Sprintf("command=\"%s %s %s %s\",no-pty", pi.Conf["script_path"],
		sshComment, pi.Conf["myproxy_server"], pi.Conf["myproxy_server_pwd"])

	suffixedPublicKey := fmt.Sprintf("%s %s", publicKey, sshComment)
	pi.Params = map[string]interface{}{
		"key_prefix": linePrefix,
		"pub_key":    suffixedPublicKey,
		"state":      pi.CredentialState,
	}
	parameterBytes, err := json.Marshal(pi)
	l.Check(err, 1, "marshaling remote script parameter")

	encodedScriptParameter := base64url.Encode(parameterBytes)
	sshTarget := fmt.Sprintf("%s@%s", pi.Conf["user"], pi.Conf["host"])

	// execute the ssh command
	remoteScript, ok := pi.Conf["remote_script"].(string)
	l.CheckOk(ok, 1, "Conf remote_script is no string")

	cmd := exec.Command("ssh", sshTarget, remoteScript, encodedScriptParameter)

	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	l.Check(err, 1, "executing ssh command")

	// checking the output of the ssh command
	var sshCmdOutput map[string]string
	err = json.Unmarshal(out.Bytes(), &sshCmdOutput)
	l.Check(err, 1, "unmarshaling output of ssh command")

	if result, ok := sshCmdOutput["result"]; ok && result == "ok" {
		return l.PluginGoodRequest(credential, sshComment)
	}
	if logMsg, ok := sshCmdOutput["log_msg"]; ok {
		return l.PluginError(logMsg)
	}
	return l.PluginError("request failed")
}

func revoke(pi l.Input) l.Output {
	parameterBytes, err := json.Marshal(pi)
	l.Check(err, 1, "marshaling parameter for remote script")

	encodedScriptParameter := base64url.Encode(parameterBytes)
	sshTarget := fmt.Sprintf("%s@%s", pi.Conf["user"], pi.Conf["host"])

	// execute the ssh command
	remoteScript, ok := pi.Conf["remote_script"].(string)
	l.CheckOk(ok, 1, "Conf remote_script is no string")
	cmd := exec.Command("ssh", sshTarget, remoteScript, encodedScriptParameter)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	l.Check(err, 1, "executing ssh command")

	// checking the output of the ssh command
	var sshCmdOutput map[string]string
	err = json.Unmarshal(out.Bytes(), &sshCmdOutput)
	l.Check(err, 1, "unmarshaling output of remote script")

	if result, ok := sshCmdOutput["result"]; ok && result == "ok" {
		return l.PluginGoodRevoke()
	}
	if logMsg, ok := sshCmdOutput["log_msg"]; ok {
		return l.PluginError(logMsg)
	}
	return l.PluginError("revocation failed")
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version: "0.1.0",
		Author:  "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		Actions: map[string]l.Action{
			"request": request,
			"revoke":  revoke,
		},
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "myproxy_server", Type: "string", Default: "master.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "myproxy_server_pwd", Type: "string", Default: ""},
			l.ConfigParamsDescriptor{Name: "script_path", Type: "string", Default: "./myproxy_get_cert.py"},
			l.ConfigParamsDescriptor{Name: "remote_script", Type: "string", Default: "./myproxy_ssh_vm.py"},
			l.ConfigParamsDescriptor{Name: "host", Type: "string", Default: "watts-x509.data.kit.edu"},
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
