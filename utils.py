import ctypes
import struct
from ctypes.util import find_library


class Utils():
    class timespec(ctypes.Structure):
        """Time specification, as described in clock_gettime(3)."""
        _fields_ = (('tv_sec', ctypes.c_long),
                    ('tv_nsec', ctypes.c_long))

    @staticmethod
    def monotonic():
        ts = Utils.timespec()
        clock_gettime(1, ctypes.pointer(ts))
        return ts.tv_sec + ts.tv_nsec / 1.0e9

    @staticmethod
    def get_monotonic_str():
        return struct.pack("<Q", int(Utils.monotonic() * 100000))[:5]


clock_gettime = ctypes.CDLL(ctypes.util.find_library('c'),
                            use_errno=True).clock_gettime
