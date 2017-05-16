#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import json
import base64
import sys
import os
import traceback

UserName = "x509"


def insert_ssh_key(KeyPrefix, Key, State):
    AuthorizedFile = os.path.expanduser(os.path.join(".ssh",
                                                     "authorized_keys"))
    if not os.path.isfile(AuthorizedFile):
        return {'result': 'error',
                'log_msg': 'no file: {}'.format(AuthorizedFile)}

    Cmd = "echo '%s %s' >> %s" % (KeyPrefix, Key, AuthorizedFile)
    if not os.system(Cmd) == 0:
        return {'result': 'error',
                'log_msg': 'inserting the line key line failed'}

    return {'result': 'ok'}


# TODO sanitize authorized_keys file
# idea: a user gets keys from multiple instances
#
# maybe split the authorized_keys file into multiple files and concat them
def revoke_ssh(UserName, State):
    LogMsg = "removal of public key failed: the cmd '%s' failed with %d"
    AuthorizedFile = os.path.expanduser(os.path.join(".ssh", "authorized_keys"))
    BackupFile = "%s%s" % (AuthorizedFile, ".backup")
    Copy = "cp %s %s" % (AuthorizedFile, BackupFile)
    Remove = "grep -v %s %s > %s" % (State, BackupFile, AuthorizedFile)
    Delete = "rm -f %s" % BackupFile
    Res = os.system(Copy)
    if Res != 0:
        return {'result': 'error', 'log_msg': LogMsg % (Copy, Res)}

    Res = os.system(Remove)
    if Res != 0 and Res != 256:
        return {'result': 'error', 'log_msg': LogMsg % (Remove, Res)}

    Res = os.system(Delete)
    if Res != 0:
        return {'result': 'error', 'log_msg': LogMsg % (Delete, Res)}

    return {'result': 'ok'}


def main():
    try:
        if not len(sys.argv) == 2:
            LogMsg = "the plugin was run without an action"
            print(json.dumps({'result': 'error',
                              'log_msg': LogMsg}))
            return

        Json = str(sys.argv[1]) + '=' * (4 - len(sys.argv[1]) % 4)
        JObject = json.loads(str(base64.urlsafe_b64decode(Json)))

        # general information
        Action = JObject['action']
        State = JObject['cred_state']
        global UserName
        UserName = JObject['watts_userid']
        Params = JObject['params']

        if Action == "request":
            KeyPrefix = Params['key_prefix']
            PubKey = Params['pub_key']
            InState = Params['state']
            print(json.dumps(insert_ssh_key(KeyPrefix, PubKey, InState)))
        elif Action == "revoke":
            print(json.dumps(revoke_ssh(UserName, State)))

    except Exception as E:
        TraceBack = traceback.format_exc(),
        LogMsg = "the plugin crashed: %s - %s" % (str(E), TraceBack)
        print json.dumps({'result': 'error', 'log_msg': LogMsg})

if __name__ == "__main__":
    main()
