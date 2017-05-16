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
	"golang.org/x/crypto/ssh"
	mrand "math/rand"
	"os/exec"
	"time"
)

const (
	letterBytes       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits     = 6                    // 6 bits to represent a letter index
	letterIdxMask     = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax      = 63 / letterIdxBits
	rsaBits           = 4096
	rsaPasswordLength = 16
)

// http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
func randStringBytesMaskImprSrc(n int) []byte {
	var src = mrand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return b
}

func generateKey() (privateKey string, publicKey string, password string) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	l.Check(err, 1, "rsa private key generation")

	passwordBytes := []byte{}
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
	}
	if rsaPasswordLength > 0 {
		passwordBytes = randStringBytesMaskImprSrc(rsaPasswordLength)
		pemBlock, err = x509.EncryptPEMBlock(
			rand.Reader, pemBlock.Type, pemBlock.Bytes, passwordBytes, x509.PEMCipherAES256)
		l.Check(err, 1, "encrypting pem block")
	}

	sshPublicKey, err := ssh.NewPublicKey(&rsaPrivateKey.PublicKey)
	l.Check(err, 1, "ssh public key generation")

	privateKeyPEM := pem.EncodeToMemory(pemBlock)
	publicKeyAuthKey := ssh.MarshalAuthorizedKey(sshPublicKey)

	// removing a trailing newline here
	privateKey = string(privateKeyPEM[:len(privateKeyPEM)-1])
	publicKey = string(publicKeyAuthKey[:len(publicKeyAuthKey)-1])
	password = string(passwordBytes)
	return
}

func request(plugin l.Plugin) l.Output {
	if _, ok := plugin.PluginInput.Params["pub_key"]; ok {
		return l.PluginError("provided key not implemented")
	} else {
		// generate a new key
		privateKey, publicKey, password := generateKey()

		// prepare parameters for the ssh command
		linePrefix := fmt.Sprintf(
			"command=\"%s %s %s %s\",no-pty",
			plugin.PluginInput.ConfigParams["script_path"],
			plugin.PluginInput.WaTTSUserID,
			plugin.PluginInput.ConfigParams["myproxy_server"],
			plugin.PluginInput.ConfigParams["myproxy_server_pwd"])

		/* the key needs to be suffixed with:
		*	a indicator of the inserting instance and the uid
		 */
		instance := plugin.PluginInput.ConfigParams["prefix"].(string)
		suffixedPublicKey := publicKey + " " + instance + "_" + plugin.PluginInput.WaTTSUserID
		parameter := map[string]interface{}{
			"action":       "request",
			"watts_userid": plugin.PluginInput.WaTTSUserID,
			"cred_state":   plugin.PluginInput.CredentialState,
			"params": map[string]string{
				"key_prefix": linePrefix,
				"pub_key":    suffixedPublicKey,
				"state":      plugin.PluginInput.CredentialState,
			},
		}
		parameterBytes, err := json.Marshal(parameter)
		l.Check(err, 1, "marshaling script json")
		encodedScriptParameter := base64url.Encode(parameterBytes)
		sshTarget := fmt.Sprintf(
			"%s@%s",
			plugin.PluginInput.ConfigParams["user"],
			plugin.PluginInput.ConfigParams["host"])

		// execute the ssh command
		cmd := exec.Command(
			"ssh",
			sshTarget,
			plugin.PluginInput.ConfigParams["remote_script"].(string),
			encodedScriptParameter)
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		l.Check(err, 1, "executing ssh command")

		// checking the output of the ssh command
		var sshCmdOutput map[string]string
		err = json.Unmarshal(out.Bytes(), &sshCmdOutput)
		l.Check(err, 1, "unmarshaling output of ssh command")

		if result, ok := sshCmdOutput["result"]; ok {
			if result == "ok" {
				// format credentials
				credential := []l.Credential{
					l.Credential{Name: "private key", Type: "string", Value: privateKey},
					l.Credential{Name: "public key", Type: "string", Value: publicKey},
					l.Credential{Name: "password", Type: "string", Value: password},
				}
				credentialState := "registerred"
				return l.PluginGoodRequest(credential, credentialState)
			}
			return l.PluginError(sshCmdOutput["log_msg"])
		}
		return l.PluginError("ssh command failed")
	}
}

func revoke(plugin l.Plugin) l.Output {
	return l.PluginError("revoke not implemented")
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
