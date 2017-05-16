package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"git.scc.kit.edu/lukasburgey/wattsPluginLib/sshKeyGen"
	"github.com/kalaspuffar/base64url"
	"os/exec"
)

func request(pi l.PluginInput, conf map[string]interface{}, params map[string]interface{}) l.Output {

	credential := []l.Credential{}
	var publicKey string

	// if the user has provided a public key we use it instead of generating a key pair
	if pk, ok := pi.Params["pub_key"]; ok {
		publicKey = fmt.Sprint(pk)
	} else {
		// generate a new key
		privateKey, publicKey, password, err := sshKeyGen.GenerateKey(4096, 16)
		l.Check(err, 1, "ssh keypair generation")
		credential = []l.Credential{
			l.Credential{Name: "private key", Type: "string", Value: privateKey},
			l.Credential{Name: "public key", Type: "string", Value: publicKey},
			l.Credential{Name: "password", Type: "string", Value: password},
		}
	}

	// prepare parameters for the ssh command
	linePrefix := fmt.Sprintf("command=\"%s %s %s %s\",no-pty", conf["script_path"],
		pi.WaTTSUserID, conf["myproxy_server"], conf["myproxy_server_pwd"])

	suffixedPublicKey := fmt.Sprintf("%s %s_%s", publicKey, conf["prefix"], pi.WaTTSUserID)
	pi.Params = map[string]interface{}{
		"key_prefix": linePrefix,
		"pub_key":    suffixedPublicKey,
		"state":      pi.CredentialState,
	}
	parameterBytes, err := json.Marshal(pi)
	l.Check(err, 1, "marshaling remote script parameter")

	encodedScriptParameter := base64url.Encode(parameterBytes)
	sshTarget := fmt.Sprintf("%s@%s", conf["user"], conf["host"])

	// execute the ssh command
	cmd := exec.Command("ssh", sshTarget, conf["remote_script"].(string), encodedScriptParameter)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	l.Check(err, 1, "executing ssh command")

	// checking the output of the ssh command
	var sshCmdOutput map[string]string
	err = json.Unmarshal(out.Bytes(), &sshCmdOutput)
	l.Check(err, 1, "unmarshaling output of ssh command")

	if result, ok := sshCmdOutput["result"]; ok && result == "ok" {
		return l.PluginGoodRequest(credential, "registerred")
	}
	if logMsg, ok := sshCmdOutput["log_msg"]; ok {
		return l.PluginError(logMsg)
	}
	return l.PluginError("request failed")
}

func revoke(pi l.PluginInput, conf map[string]interface{}, params map[string]interface{}) l.Output {
	parameterBytes, err := json.Marshal(pi)
	l.Check(err, 1, "marshaling parameter for remote script")

	encodedScriptParameter := base64url.Encode(parameterBytes)
	sshTarget := fmt.Sprintf("%s@%s", conf["user"], conf["host"])

	// execute the ssh command
	cmd := exec.Command("ssh", sshTarget, conf["remote_script"].(string), encodedScriptParameter)
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
		Version:       "0.1.0",
		Author:        "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		ActionRequest: request,
		ActionRevoke:  revoke,
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "myproxy_server", Type: "string", Default: "master.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "myproxy_server_pwd", Type: "string", Default: ""},
			l.ConfigParamsDescriptor{Name: "script_path", Type: "string", Default: "./ssh_trigger.py"},
			l.ConfigParamsDescriptor{Name: "remote_script", Type: "string", Default: "./myproxy_ssh_vm.py"},
			l.ConfigParamsDescriptor{Name: "host", Type: "string", Default: "watts-x509.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "user", Type: "string", Default: "x509"},
			l.ConfigParamsDescriptor{Name: "prefix", Type: "string", Default: "foobar"},
		},
		RequestParams: []l.RequestParamsDescriptor{
			l.RequestParamsDescriptor{
				Key: "pub_key", Name: "public key", Description: "the public key of the service", Type: "textarea",
				Mandatory: false},
		},
	}
	l.PluginRun(pluginDescriptor)
}
