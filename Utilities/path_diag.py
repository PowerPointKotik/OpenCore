import os
import subprocess
import sys

p = os.environ.get('PATH', '')
print('PYTHON_VERSION=' + sys.version.split()[0])
print('PATH_LEN=' + str(len(p)))
print('PATH_FIRST_400=' + p[:400])
print('PATH_LAST_300=' + p[-300:])
print('HAS_SYSTEM32=' + str('System32' in p))
binwin = r'D:\a\OpenCore\OpenCore\UDK\BaseTools\Bin\Win32'
print('GEN_SEC_EXISTS=' + str(os.path.exists(os.path.join(binwin, 'GenSec.exe'))))
print('IMAGE_TOOL_EXISTS=' + str(os.path.exists(os.path.join(binwin, 'ImageTool.exe'))))

def run(cmdline):
    try:
        out = subprocess.check_output(cmdline, shell=True, stderr=subprocess.STDOUT,
                                      timeout=30)
        return out.decode(errors='replace')
    except subprocess.CalledProcessError as e:
        return 'RC=%d\n%s' % (e.returncode, (e.output or b'').decode(errors='replace'))
    except Exception as e:
        return 'EXC=%r' % (e,)

print('--- CMD_WHERE ---')
print(run('where GenSec 2>&1 & echo --- & where ImageTool 2>&1 & echo --- & where where 2>&1'))
print('--- CMD_GENSEC_DIRECT ---')
print(run('GenSec 2>&1'))
print('--- CMD_DIR_TEST ---')
print(run('dir %s\\GenSec.exe 2>&1' % binwin))
