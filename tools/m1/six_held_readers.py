import os,ctypes,ctypes.wintypes,contextlib
INPUT_CODES={"INPUT_FILE"}
INPUT_PHASES={"prefix"}
class InputFailure(ValueError):
    def __init__(self,code,phase="admission",**data):
        self.code=code if code in INPUT_CODES else "INPUT_INTERNAL"
        self.phase=phase if phase in INPUT_PHASES else "admission"
        self.data=data
        super().__init__(self.code)

def input_require(ok,code="INPUT_GUARD",phase="admission"):
    if not ok:raise InputFailure(code,phase)

class _INPUT_FILE_INFO(ctypes.Structure):
    _fields_=[("attrs",ctypes.wintypes.DWORD),("created",ctypes.wintypes.FILETIME),
      ("accessed",ctypes.wintypes.FILETIME),("written",ctypes.wintypes.FILETIME),
      ("volume",ctypes.wintypes.DWORD),("sizeHigh",ctypes.wintypes.DWORD),
      ("sizeLow",ctypes.wintypes.DWORD),("links",ctypes.wintypes.DWORD),
      ("indexHigh",ctypes.wintypes.DWORD),("indexLow",ctypes.wintypes.DWORD)]

def _file_identity(kernel,handle):
    info=_INPUT_FILE_INFO()
    input_require(bool(kernel.GetFileInformationByHandle(handle,ctypes.byref(info))),"INPUT_FILE","prefix")
    input_require(not info.attrs & (0x10|0x400) and info.links>=1,"INPUT_FILE","prefix")
    return {"volume":info.volume,"fileIndex":(info.indexHigh<<32)|info.indexLow,
            "bytes":(info.sizeHigh<<32)|info.sizeLow,
            "created":(info.created.dwHighDateTime<<32)|info.created.dwLowDateTime,
            "written":(info.written.dwHighDateTime<<32)|info.written.dwLowDateTime,"links":info.links}

@contextlib.contextmanager
def input_held_read(path):
    import msvcrt
    input_require(os.name=="nt" and str(path).lower() in ('c:\\windows\\system32\\napinsp.dll', 'c:\\windows\\system32\\dsparse.dll', 'c:\\windows\\system32\\winrnr.dll', 'c:\\windows\\system32\\nlansp_c.dll', 'c:\\windows\\system32\\wshbth.dll', 'c:\\windows\\system32\\kernel.appcore.dll'),"INPUT_FILE","prefix")
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    kernel.CreateFileW.argtypes=[ctypes.wintypes.LPCWSTR,ctypes.wintypes.DWORD,
      ctypes.wintypes.DWORD,ctypes.c_void_p,ctypes.wintypes.DWORD,
      ctypes.wintypes.DWORD,ctypes.wintypes.HANDLE]
    kernel.CreateFileW.restype=ctypes.wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes=[ctypes.wintypes.HANDLE,ctypes.POINTER(_INPUT_FILE_INFO)]
    kernel.CloseHandle.argtypes=[ctypes.wintypes.HANDLE]
    handle=kernel.CreateFileW(str(path),0x80000000,1,None,3,0x00200000,None)
    input_require(handle not in (None,ctypes.c_void_p(-1).value),"INPUT_FILE","prefix")
    stream=None
    try:
        first=_file_identity(kernel,handle)
        fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        stream=os.fdopen(fd,"rb");handle=None
        yield stream,first
        actual=_file_identity(kernel,msvcrt.get_osfhandle(stream.fileno()))
        input_require(actual==first,"INPUT_FILE","prefix")
    finally:
        if stream is not None:stream.close()
        elif handle is not None:kernel.CloseHandle(handle)
