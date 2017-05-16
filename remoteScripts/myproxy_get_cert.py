#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import traceback
from subprocess import Popen, PIPE


def main():
    try:
        if len(sys.argv) == 4:
            watts_userid = str(sys.argv[1])
            host = str(sys.argv[2])
            password = str(sys.argv[3])
            p = Popen(['myproxy-logon',
                       '-l', watts_userid, '-s', host, '-S', '-o', '-'],
                      stdin=PIPE, stdout=PIPE, stderr=PIPE)

            stdout, stderr = p.communicate(input=password)
            print stdout
            print stderr
        else:
            print "usage: <watts_userid> <host> <pw>"

    except Exception as E:
        TraceBack = traceback.format_exc(),
        print "error: %s - %s" % (str(E), TraceBack)

if __name__ == "__main__":
    main()
