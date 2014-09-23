'''Subcommand module `add`; contains only a single class `Command`'''

# Copyright (c) 2012-2014  Tom Willemse <tom@ryuslash.org>
# Copyright (c) 2011-2014  Benjamin Althues <benjamin@babab.nl>
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

from dispass import algos
from dispass.common import CommandBase
from dispass.dispass import settings
from dispass.filehandler import Filehandler


class Command(CommandBase):
    '''Update the information relating to a label'''

    usagestr = (
        'usage: dispass update [-n] [-s] <label> '
        '[<size>]:[<algorithm>]:[<sequence_number>]\n'
        '       dispass update [-h]'
    )

    description = (
        'Update information for a label'
    )

    optionList = (
        ('help',    ('h', False, 'show this help information')),
        ('dry-run', ('n', False, 'do not actually update label in labelfile')),
        ('silent',  ('s', False, 'do not print success message')),
    )

    def run(self):
        '''Parse the arguments and update them using `FileHandler.update`.'''

        if self.parentFlags['file']:
            lf = Filehandler(settings, file_location=self.parentFlags['file'])
        else:
            lf = Filehandler(settings)

        if not len(self.args) == 2 or self.flags['help']:
            print self.usage
            return

        if not lf.file_found:
            if not lf.promptForCreation(silent=self.flags['silent']):
                return 1

        labelname = self.args[0]
        params = self.args[1].split(':')

        try:
            length = int(params[0]) if params[0] else None
        except ValueError:
            length = None

        if params[1] and params[1] in algos.algorithms:
            algo = params[1]
        else:
            algo = None

        seqno = None
        if algo != 'dispass1':
            try:
                seqno = params[2] if params[2] else None
            except ValueError:
                pass

        if lf.update(labelname, length=length, algo=algo, seqno=seqno):
            if not self.flags['silent']:
                print("Label '{name}' updated".format(name=labelname))
        else:
            if not self.flags['silent']:
                print("Label '{name}' could not be updated"
                      .format(name=labelname))

        if not self.flags['dry-run']:
            lf.save()
