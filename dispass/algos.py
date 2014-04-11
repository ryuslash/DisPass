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

import base64
import hashlib
import itertools

algorithms = ('dispass1', 'dispass2', 'dispass3')
'''A tuple of registrered algorithms, used for validation of user input'''


class FakeOrd(object):
    '''Create fake ordinal numbers based on the characters in a string.

    Alphanumeric characters are not entirely contiguous (`chr(ord('A') +
    1)` is indeed 'B', but `chr(ord('Z') + 1)` is not 'a', or in fact
    even an alphanumeric character. When selecting characters from
    character sets these gaps create ranges of characters that can never
    be used because of the limited set of characters we start from.

    Upon instantiation the characters in the original string have
    duplicates removed and are sorted, then a mapping is created for
    each character to a number. The start of the sequence depends on the
    first character in the sorted list.

    Calling the created object with a character returns the matching
    integer value.

    '''
    def __init__(self, original):
        self.mapping = {}
        iterator = None

        for c in sorted(set(original)):
            if iterator is None:
                iterator = itertools.count(ord(c))
            if c not in self.mapping:
                self.mapping[c] = iterator.next()

    def __call__(self, character):
        return self.mapping[character]


def cxrange(char1, char2):
    '''Return a generator for a range of characters from `char1` up to and
    including `char2`.

    '''
    for c in xrange(ord(char1), ord(char2) + 1):
        yield chr(c)


def crange(char1, char2):
    '''Return a list of characters from `char1` up to and including `char2`.

    '''
    return list(cxrange(char1, char2))


def algoObject(algoname):
    '''Return an algorithm object

    :Parameters:
        - `algoname`: String. Name of the algorithm

    :Return:
        - An algorithm object or False

    '''
    if algoname == 'dispass1':
        return Dispass1()
    elif algoname == 'dispass2':
        return Dispass2()
    elif algoname == 'dispass3':
        return Dispass3()
    else:
        return False


class Dispass1:
    '''Dispass1 algorithm

    Tests:

    >>> dispass1 = Dispass1()
    >>> dispass1.digest('test', 'qqqqqqqq')
    'Y2Y4Y2Y0Yzg5Nzc1Yzc2MmI4OTU0ND'
    >>> dispass1.digest('test2', 'qqqqqqqq', 50)
    'NmQzNjUzZTlhNTc4NWFlNTU5ZTVkZGQ5ZTc2NzliZjgzZDQ1Zj'
    '''

    @staticmethod
    def digest(label, password, length=30, seqno=None, charset=None):
        '''Create and return secure hash of message

        A secure hash/message digest formed by hashing a string (formed by
        concatenating label+password) with the sha512 algorithm, encoding
        this hash with base64 and stripping it down to the first `length`
        characters.

        :Parameters:
            - `label`: String. Labelname
            - `password`: String. The input password
            - `length`: Length of output hash (optional)
            - `seqno`: Sequence number. Not used in Dispass1

        :Return:
            - The secure hash of `label` + `password`
        '''

        sha = hashlib.sha512()
        sha.update(str(label) + str(password))
        r = base64.b64encode(sha.hexdigest(), '49').replace('=', '')

        return str(r[:length])


class Dispass2:
    '''Dispass2 algorithm

    Tests:

    >>> dispass2 = Dispass2()
    >>> dispass2.digest('test', 'qqqqqqqq')
    'ZTdiNGNkYmQ2ZjFmNzc3NGFjZWEwMz'
    >>> dispass2.digest('test2', 'qqqqqqqq', 50, 10)
    'NGEwNjMxMzZiMzljODVmODk4OWQ1ZmE4YTRlY2E4ODZkZjZlZW'
    '''

    @staticmethod
    def digest(label, password, length=30, seqno=1, charset=None):
        '''Create and return secure hash of message

        A secure hash/message digest formed by hashing a string (formed by
        concatenating label+seqno+password) with the sha512 algorithm, encoding
        this hash with base64 and stripping it down to the first `length`
        characters.

        :Parameters:
            - `label`: String. Labelname
            - `password`: String. The input password
            - `length`: Length of output hash (optional)
            - `seqno`: Integer. Sequence number.

        :Return:
            - The secure hash of `label` + `seqno` + `password`
        '''

        sha = hashlib.sha512()
        sha.update(str(label) + str(seqno) + str(password))
        r = base64.b64encode(sha.hexdigest(), '49').replace('=', '')

        return str(r[:length])


class Dispass3:
    '''Dspass3 algorithm

    Tests:

    >>> dispass3 = Dispass3()
    >>> dispass3.digest('test', 'qqqqqqqq')
    'ZTdiNGNkYmQ2ZjFmNzc3NGFjZWEwMz'
    >>> dispass3.digest('test2', 'qqqqqqqq', 50, 10)
    'NGEwNjMxMzZiMzljODVmODk4OWQ1ZmE4YTRlY2E4ODZkZjZlZW'
    >>> dispass3.digest('test3', 'qqqqqqqq', charset='light')
    '765c1Z7Y1f9a8b_X2d3e8bcf8Z0W14'
    >>> dispass3.digest('test4', 'qqqqqqqq', 50, 10, 'light')
    '6XaX734g698Y510fb38W738Waefd6ech532e6e4Z6X6e6i_i6i'
    >>> dispass3.digest('test5', 'qqqqqqqq', 50, 10, 'full')
    '3Z#%@^0W2^4)987$2_5^9^#$3^Y)@6@*9^(*3Z2X9^1^9^*)36'
    '''

    charsets = {'light': (crange('a', 'z')
                          + crange('A', 'Z')
                          + crange('0', '9')
                          + ['_']),
                'full': (crange('a', 'z')
                         + crange('A', 'Z')
                         + crange('0', '9')
                         + list('@#$%^*()_-=+/?.,~[]{}|;:!\\&`'))}

    @staticmethod
    def digest(label, password, length=30, seqno=1, charset=None):
        '''Create and return a secure hash of message

        A secure hash/message digest formed by hasing a string (formed
        by concatennating label+seqno+password) with the sha512
        algorithm, encoding this hash with base64 and stripping it down
        to the first `length` characters.

        :Parameters:
            - `label`: String. Labelname
            - `password`: String. The input password
            - `length`: Length of output hash (optional)
            - `seqno`: Integer. Sequence number.

        :Return:
            - The secure hash of `label` + `seqno` + `password`

        '''

        sha = hashlib.sha512()
        sha.update(str(label) + str(seqno) + str(password))
        r = base64.b64encode(sha.hexdigest(), '49').replace('=', '')[:length]

        if charset and charset in Dispass3.charsets:
            order = FakeOrd(r)
            chars = Dispass3.charsets[charset]
            charcount = len(chars)

            return ''.join([chars[order(c) % charcount] for c in r])

        return str(r)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
