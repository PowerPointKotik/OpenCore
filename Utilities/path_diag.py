import os
import struct
import subprocess
import sys

import argparse


def dump_pe(path):
    print('PE_DUMP ' + path)
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print('  OPEN_FAIL: %s' % (e,))
        return
    print('  SIZE=%d' % len(data))
    if len(data) < 0x40 or data[:2] != b'MZ':
        print('  NOT_MZ')
        return
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        print('  NO_PE_SIG')
        return
    coff = e_lfanew + 4
    machine, numsections, timestamp = struct.unpack_from('<HHI', data, coff)
    size_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic == 0x10B:
        entry, ibase = struct.unpack_from('<II', data, opt + 16)
        sect_align, file_align = struct.unpack_from('<II', data, opt + 32)
        img_size, hdr_size = struct.unpack_from('<II', data, opt + 56)
        subsystem = struct.unpack_from('<H', data, opt + 68)[0]
        num_rva = struct.unpack_from('<I', data, opt + 92)[0]
        datadir = opt + 96
    elif magic == 0x20B:
        entry = struct.unpack_from('<I', data, opt + 16)[0]
        ibase = struct.unpack_from('<Q', data, opt + 24)[0]
        sect_align, file_align = struct.unpack_from('<II', data, opt + 32)
        img_size, hdr_size = struct.unpack_from('<II', data, opt + 56)
        subsystem = struct.unpack_from('<H', data, opt + 68)[0]
        num_rva = struct.unpack_from('<I', data, opt + 108)[0]
        datadir = opt + 112
    else:
        print('  BAD_OPT_MAGIC=0x%X' % magic)
        return
    print('  machine=0x%04X sections=%d ts=0x%08X entry=0x%X base=0x%X' % (
        machine, numsections, timestamp, entry, ibase))
    print('  SectionAlignment=0x%X FileAlignment=0x%X SizeOfImage=0x%X SizeOfHeaders=0x%X subsystem=%d numRva=%d' % (
        sect_align, file_align, img_size, hdr_size, subsystem, num_rva))
    reloc = None
    debug = None
    if num_rva > 5:
        reloc = struct.unpack_from('<II', data, datadir + 5 * 8)
        debug = struct.unpack_from('<II', data, datadir + 6 * 8)
        print('  relocDir VA=0x%X size=0x%X' % reloc)
        print('  debugDir VA=0x%X size=0x%X' % debug)
    sect = coff + 20 + size_opt
    raw_for = []
    for i in range(numsections):
        sh = sect + i * 40
        name = data[sh:sh + 8].rstrip(b'\0')
        vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', data, sh + 8)
        chars = struct.unpack_from('<I', data, sh + 36)[0]
        print('  sect[%d] %-8s VA=0x%X VSize=0x%X RawSize=0x%X RawPtr=0x%X chars=0x%08X' % (
            i, name.decode('ascii', 'replace'), va, vsize, rawsize, rawptr, chars))
        raw_for.append((va, vsize, rawsize, rawptr))
    if debug and debug[1]:
        drva, dsize = debug
        for va, vsize, rawsize, rawptr in raw_for:
            if va <= drva < va + max(vsize, rawsize):
                off = rawptr + (drva - va)
                if off + 28 <= len(data):
                    dtype, dsz = struct.unpack_from('<II', data, off)
                    if dtype == 2:
                        pdboff = off + 24
                        pdb = data[pdboff:off + dsize]
                        nul = pdb.find(b'\0')
                        if nul >= 0:
                            pdb = pdb[:nul]
                        print('  PDB: %s' % pdb.decode('ascii', 'replace'))
                    else:
                        print('  DEBUG_TYPE=%d' % dtype)
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pe', action='append', default=None, metavar='FILE')
    args = parser.parse_args()
    if args.pe:
        for f in args.pe:
            dump_pe(f)
        return
    p = os.environ.get('PATH', '')
    env_size = sum(len(k) + len(v) + 2 for k, v in os.environ.items())
    print('PYTHON_VERSION=' + sys.version.split()[0])
    print('ENV_BLOCK_SIZE=' + str(env_size))
    print('PATH_LEN=' + str(len(p)))
print('PATH_FIRST_300=' + p[:300])
print('PATH_LAST_300=' + p[-300:])
print('HAS_SYSTEM32=' + str('System32' in p))
binwin = r'D:\a\OpenCore\OpenCore\UDK\BaseTools\Bin\Win32'
print('GEN_SEC_EXISTS=' + str(os.path.exists(os.path.join(binwin, 'GenSec.exe'))))
print('IMAGE_TOOL_EXISTS=' + str(os.path.exists(os.path.join(binwin, 'ImageTool.exe'))))


def run(cmdline, env=None):
    try:
        out = subprocess.check_output(cmdline, shell=True, stderr=subprocess.STDOUT,
                                      timeout=30, env=env)
        return out.decode(errors='replace')
    except subprocess.CalledProcessError as e:
        return 'RC=%d\n%s' % (e.returncode, (e.output or b'').decode(errors='replace'))
    except Exception as e:
        return 'EXC=%r' % (e,)


print('--- CMD_ECHO_PATH ---')
print(run('echo %PATH%'))
print('--- CMD_WHERE_FULL_PATH ---')
print(run('where GenSec 2>&1 & echo --- & where where 2>&1'))
clean = os.pathsep.join([binwin,
                         r'D:\a\OpenCore\OpenCore\UDK\BaseTools\BinWrappers\WindowsLike',
                         r'C:\Windows\System32'])
print('--- CMD_WHERE_CLEAN_PATH ---')
print(run('where GenSec 2>&1 & echo --- & GenSec 2>&1', env=dict(os.environ, PATH=clean)))
