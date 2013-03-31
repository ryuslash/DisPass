# Copyright (c) 2011, 2012, 2013  Benjamin Althues <benjamin@babab.nl>
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

import exceptions
import importlib

from dispass.common import CommandBase
from dispass.dispass import Dispass, settings


class Command(CommandBase):
    usagestr = 'usage: dispass help [<command>]'
    description = 'Show help information'

    def run(self):
        main = Dispass()

        if not self.args:
            main.usage()
            return
        else:
            try:
                mod = importlib.import_module('dispass.commands.'
                                              + self.args[0])
                cmd = mod.Command(settings=settings, argv=self.args[1:])
            except ImportError:
                print('error: command {cmd} does not exist'
                      .format(cmd=self.args[0]))
                return 1
            except exceptions.KeyboardInterrupt:
                print('\nOk, bye')
                return 1

        print(cmd.usage)
