'''Generate and disperse/dispell passwords'''

# Copyright (c) 2011-2012 Benjamin Althues <benjamin@babab.nl>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

__docformat__ = 'restructuredtext'
__author__ = "Benjamin Althues"
__copyright__ = "Copyright (C) 2011-2012 Benjamin Althues"
__version_info__ = (0, 1, 0, 'alpha', 7)
__version__ = '0.1a7'
versionStr = 'DisPass ' + __version__

import getopt
import os
import sys

import cli
import gui

def usage():
        print "%s - http://dispass.babab.nl/" % (versionStr)
        print
        print "When DisPass is executed as 'gdispass' or 'dispass -g',"
        print 'the graphical version will be started.'
        print
        print 'USAGE: dispass [-co] label [label2] [label3] [...]'
        print '       dispass -g | -h | -V'
        print '       gdispass'
        print
        print 'Options:'
        print '-c, --create    use if this passphrase is new (check input PW)'
        print '-g, --gui       start guided graphical version of DisPass'
        print '-h, --help      show this help and exit'
        print '-o, --output    output passphrases to stdout (instead of the '
        print '                more secure way of displaying via curses)'
        print '-V, --version   show full version information and exit'

def main(argv):
    commandLineIf = cli.CLI()

    try:
        opts, args = getopt.getopt(argv[1:], "cghoV",
                ["create", "gui", "help", "output", "version"])
    except getopt.GetoptError, err:
        print str(err), "\n"
        usage()
        sys.exit(2)

    if args:
        labels = args
    else:
        labels = False

    pwTypoCheck = False
    for o, a in opts:
        if o in ("-g", "--gui"):
            gui.GUI()
            return
        elif o in ("-c", "--create"):
            pwTypoCheck = True
        elif o in ("-o", "--output"):
            commandLineIf.setCurses(False)
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-V", "--version"):
            print versionStr, '-', __version_info__, 'running on', os.name
            sys.exit()
        else:
            assert False, "unhandled option"

    if labels:
        commandLineIf.interactive(labels, pwTypoCheck)
    else:
        usage()

if __name__ == '__main__':
    main(sys.argv)