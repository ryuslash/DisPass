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


class Command(CommandBase):
    usagestr = 'usage: dispass list [-h] [--script]'
    description = (
        'Print a formatted table of labelfile contents\n\n'

        'If --script is passed the output will be optimized for easy\n'
        'parsing by other programs and scripts by not printing the header\n'
        'and always printing one entry on a single line using the\n'
        'following positions:\n\n'

        'Column  1-50: label            50 chars wide\n'
        'Column 52-54: length            3 chars wide\n'
        'Column 56-70: hash algo        15 chars wide\n'
        'Column 72-74: sequence number   3 chars wide'
    )
    optionList = (
        ('help',        ('h', False, 'show this help information')),
        ('script',      ('', False, 'output in fixed columns')),
    )

    def run(self):
        if self.flags['help']:
            print self.usage
            return

        if self.parentFlags['file']:
            lf = Filehandler(settings, file_location=self.parentFlags['file'])
        else:
            lf = Filehandler(settings)

        if not lf.file_found:
            print('error: could not load labelfile at "{loc}"'
                  .format(loc=lf.file_location))
            return 1

        lf.printLabels(self.flags['script'])