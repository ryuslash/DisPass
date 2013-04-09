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

from dispass.common import CommandBase
from dispass.dispass import settings
from dispass.filehandler import Filehandler
from dispass.interactive_editor import InteractiveEditor


class Command(CommandBase):
    usagestr = ('usage: dispass rm [-n] [-s] <labelname>\n'
                '       dispass rm [-i] [-h]')
    description = 'Remove label from labelfile'
    optionList = (
        ('interactive', ('i', False, 'add label in an interactive manner')),
        ('help',    ('h', False, 'show this help information')),
        ('dry-run', ('n', False,
                     'do not actually remove label from labelfile')),
        ('silent',  ('s', False, 'do not print success message')),
    )

    def run(self):
        if self.parentFlags['file']:
            lf = Filehandler(settings, file_location=self.parentFlags['file'])
        else:
            lf = Filehandler(settings)

        if not lf.file_found:
            if not lf.promptForCreation(silent=self.flags['silent']):
                return 1

        if self.flags['interactive']:
            InteractiveEditor(self.settings, lf, interactive=False).remove()
            return 0

        if not self.args or self.flags['help']:
            print self.usage
            return 0

        if lf.remove(self.args[0]):
            if not self.flags['dry-run']:
                lf.save()
            if not self.flags['silent']:
                print('Label removed')
            return 0
        else:
            print("Label doesn't exist in labelfile")
            return 1