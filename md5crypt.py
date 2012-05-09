import os
import inspect
import numpy
import ctypes
import random
import subprocess

_libmd5crypt = numpy.ctypeslib.load_library('libmd5crypt',
        os.path.dirname(inspect.getfile(inspect.currentframe())))

_libmd5crypt.md5crypt.restype = ctypes.c_char_p
_libmd5crypt.md5crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

def md5crypt(password, salt):
    return _libmd5crypt.md5crypt(password, salt)


def test():
    pass_phrases = ["".join(map(chr, random.sample(range(ord('A'), ord('Z')) +
                                                   range(ord('a'), ord('z')) +
                                                   range(ord('0'), ord('9')), random.randint(1, 10))))
                                        for index in xrange(20)]

    for phrase in pass_phrases:
        true_md5 = subprocess.Popen(['openssl', 'passwd', '-1', '-salt', phrase, phrase],
            stdout = subprocess.PIPE).communicate()[0].strip().strip('\n')
        if true_md5 != md5crypt(phrase, phrase):
            print "Failed! password: %s salt: %s true: %s calc: %s" % (phrase, phrase, true_md5, md5crypt(phrase, phrase))
            exit(0)
    print "OK"



