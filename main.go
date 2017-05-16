package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"github.com/kalaspuffar/base64url"
	keygen "github.com/night-codes/go-keygen"
	"golang.org/x/crypto/ssh"
	"os/exec"
)

const (
	rsaBits           = 4096
	rsaPasswordLength = 16
)

func generateKey() (privateKey string, publicKey string, password string) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	l.Check(err, 1, "rsa private key generation")

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
	}
	if rsaPasswordLength > 0 {
		password = keygen.NewPass(rsaPasswordLength)
		pemBlock, err = x509.EncryptPEMBlock(
			rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(password), x509.PEMCipherAES256)
		l.Check(err, 1, "encrypting pem block")
	}

	sshPublicKey, err := ssh.NewPublicKey(&rsaPrivateKey.PublicKey)
	l.Check(err, 1, "ssh public key generation")

	privateKeyPEM := pem.EncodeToMemory(pemBlock)
	publicKeyAuthKey := ssh.MarshalAuthorizedKey(sshPublicKey)

	// removing a trailing newline here
	privateKey = string(privateKeyPEM[:len(privateKeyPEM)-1])
	publicKey = string(publicKeyAuthKey[:len(publicKeyAuthKey)-1])
	return
}

func request(plugin l.Plugin) l.Output {
	pi := plugin.PluginInput
	conf := pi.ConfigParams

	credential := []l.Credential{}
	var publicKey string

	// if the user has provided a public key we use it instead of generating a key pair
	if pk, ok := pi.Params["pub_key"]; ok {
		publicKey = fmt.Sprint(pk)
	} else {
		// generate a new key
		privateKey, publicKey, password := generateKey()
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

func revoke(plugin l.Plugin) l.Output {
	pi := plugin.PluginInput
	conf := pi.ConfigParams

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
