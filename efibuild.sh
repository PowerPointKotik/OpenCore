#!/bin/bash

unset WORKSPACE
unset PACKAGES_PATH

BUILDDIR=$(pwd)
ROOTDIR="$BUILDDIR"

if [ "$NEW_BUILDSYSTEM" = "" ]; then
  NEW_BUILDSYSTEM=0
fi

if [ "$OFFLINE_MODE" = "" ]; then
  OFFLINE_MODE=0
fi

is_array()
{
    # Detects if argument is an array, returns 1 on success, 0 otherwise
    [ -z "$1" ] && echo 0
    if [ -n "$BASH" ]; then
      declare -p "${1}" 2> /dev/null | grep 'declare \-a' >/dev/null && echo 1
    fi
    echo 0
}

prompt() {
  echo "$1"
  if [ "$FORCE_INSTALL" != "1" ]; then
    read -rp "Enter [Y]es to continue: " v
    if [ "$v" != "Y" ] && [ "$v" != "y" ]; then
      exit 1
    fi
  fi
}

setcommitauthor() {
  git config user.name ocbuild
  git config user.email ocbuild@acidanthera.local
  git config commit.gpgsign false
}

updaterepo() {
  if [ ! -d "$2" ]; then
    git clone "$1" -b "$3" --depth=1 "$2" || exit 1
    pushd "$2" >/dev/null || exit 1
    echo "Cloned ${1} at commit $(git rev-parse --short=8 HEAD)."
  else
    pushd "$2" >/dev/null || exit 1
  fi
  git pull --rebase --autostash
  if [ "$2" != "UDK" ] && [ "$(unamer)" != "Windows" ]; then
    sym=$(find . -not -type d -not -path "./.git/*" -not -path "./coreboot/*" -not -path "./UDK/*" -exec file "{}" ";" | grep CRLF)
    if [ "${sym}" != "" ]; then
      echo "Repository $1 named $2 contains CRLF line endings"
      echo "$sym"
      exit 1
    fi
  fi
  if [ "$2" = "UDK" ] && [ "$DISCARD_SUBMODULES" != "" ] && [ ! -f submodules.ready ]; then
    setcommitauthor
    for module_to_discard in "${DISCARD_SUBMODULES[@]}" ; do
      rm -rf "${module_to_discard}"
    done
    touch submodules.ready
  fi
  git submodule update --init --recommend-shallow || exit 1
  # Remove any leftover submodule directories after update
  for module_to_discard in "${DISCARD_SUBMODULES[@]}" ; do
    rm -rf "${module_to_discard}"
  done
  popd >/dev/null || exit 1
}

abortbuild() {
  echo "Build failed!"
  tail -120 build.log
  exit 1
}

pingme() {
  local timeout=200 # in 30s
  local count=0
  local cmd_pid=$1
  shift

  while [ $count -lt $timeout ]; do
    count=$(( count + 1 ))
    printf "."
    sleep 30
  done

  ## ShellCheck Exception(s)
  ## https://github.com/koalaman/shellcheck/wiki/SC2028
  ## https://github.com/koalaman/shellcheck/wiki/SC2145
  # shellcheck disable=SC2028,SC2145
  echo "\n\033[31;1mTimeout reached. Terminating $@.\033[0m"
  kill -9 "${cmd_pid}"
}

buildme() {
  local cmd_pid
  local mon_pid
  local result

  build "$@" &>build.log &
  cmd_pid=$!

  pingme $! build "$@" &
  mon_pid=$!

  ## ShellCheck Exception(s)
  ## https://github.com/koalaman/shellcheck/wiki/SC2069
  # shellcheck disable=SC2069
  { wait $cmd_pid 2>/dev/null; result=$?; ps -p$mon_pid 2>&1>/dev/null && kill $mon_pid; } || return 1
  return $result
}

symlink() {
  if [ "$(unamer)" = "Windows" ]; then
    rm -rf "$2"
    mkdir -p "$2" || exit 1
    for i in "$1"/Legacy "$1"/Platform "$1"/Application "$1"/Library "$1"/Utilities "$1"/Include "$1"/User "$1"/Staging "$1"/Tests "$1"/Patches "$1"/Docs ; do
      if [ -e "${i}" ]; then
        cp -r "${i}" "$2" || exit 1
      fi
    done
    # Copy root-level package files to OpenCorePkg directory
    for f in "$1"/*.dsc "$1"/*.fdf "$1"/*.dec "$1"/*.fdf.inc ; do
      if [ -f "${f}" ]; then
        cp "${f}" "$2/" || exit 1
      fi
    done
  else
    rm -rf "$2"
    ln -s "$1" "$2" || exit 1
  fi
}

unamer() {
  NAME="$(uname)"

  if [ "$(echo "${NAME}" | grep MINGW)" != "" ] || [ "$(echo "${NAME}" | grep MSYS)" != "" ]; then
    echo "Windows"
  else
    echo "${NAME}"
  fi
}

echo "Building on $(unamer)"

if [ "$(unamer)" = "Windows" ]; then
    cmd <<< 'chcp 437'
    # Find Python for nmake - must be available as 'python' command in Windows PATH
    # GitHub Actions installs Python in hostedtoolcache, may need explicit setup
    # Note: command -v python works in bash but not in cmd, need to check cmd too
    if cmd /d /c 'where python >/dev/null 2>&1' 2>/dev/null; then
      echo "Found python in cmd PATH at: $(cmd /d /c 'where python' 2>/dev/null | tr -d '\r')"
    elif command -v python >/dev/null 2>&1; then
      # Python found in bash but not cmd - this is GitHub Actions behavior
      echo "Found python at: $(which python) (bash only, will resolve for cmd)"
    elif [ -d "/c/ProgramData/chocolatey/lib/python3" ]; then
      for PYBIN in /c/ProgramData/chocolatey/lib/python3*/tools/python.exe; do
        if [ -f "$PYBIN" ]; then
          PATH="$(dirname "$PYBIN"):${PATH}"
          export PATH
          echo "Found python in chocolatey at: $PYBIN"
          break
        fi
      done
    fi
    # Set PYTHON_COMMAND - must be a path that works in cmd context for nmake
    if [ -n "$PYTHON_COMMAND" ]; then
      # Validate that PYTHON_COMMAND is a real Windows path (contains drive letter)
      if [[ "$PYTHON_COMMAND" != *":"* ]] || [[ "$PYTHON_COMMAND" == "python" ]] || [[ "$PYTHON_COMMAND" == "python3" ]]; then
        echo "PYTHON_COMMAND '$PYTHON_COMMAND' is invalid, finding proper path..."
        PYTHON_COMMAND=""
      fi
    fi
    if [ -z "$PYTHON_COMMAND" ] && [ -n "$pythonLocation" ]; then
      # setup-python provides pythonLocation - construct the python.exe path for nmake
      export PYTHON_COMMAND="$pythonLocation\\python.exe"
      echo "Set PYTHON_COMMAND=$PYTHON_COMMAND from setup-python"
    elif [ -n "$PYTHON_COMMAND" ]; then
      echo "Using existing PYTHON_COMMAND: $PYTHON_COMMAND"
    elif command -v py >/dev/null 2>&1; then
      # Use py launcher to get the actual python.exe directory and construct full path
      PYTHON_DIR=$(cmd /d /c 'py -3 -c "import os, sys; print(os.path.dirname(sys.executable))"' 2>/dev/null | tr -d '\r' | tail -1)
      echo "DEBUG: Python directory from py launcher: '$PYTHON_DIR'"
      if [ -n "$PYTHON_DIR" ] && [[ "$PYTHON_DIR" == *":"* ]]; then
        export PYTHON_COMMAND="${PYTHON_DIR}\\python.exe"
        echo "Set PYTHON_COMMAND=$PYTHON_COMMAND for nmake compatibility"
      else
        echo "Warning: Could not determine Python location - nmake may fail"
      fi
    else
      echo "Warning: python not available - nmake may fail"
    fi
  fi

if [ "${SELFPKG}" = "" ]; then
  echo "You are required to set SELFPKG variable!"
  exit 1
fi

if [ "${SELFPKG_DIR}" = "" ]; then
  SELFPKG_DIR="${SELFPKG}"
fi

if [ "${BUILDDIR}" != "$(printf "%s\n" "${BUILDDIR}")" ] ; then
  echo "EDK2 build system may still fail to support directories with spaces!"
  exit 1
fi

# On Windows nasm and python may not be in PATH, also setup before tool checks.
if [ "$(unamer)" = "Windows" ]; then
  # Preserve existing PATH but add common tool locations at the front
  export PATH="/c/ProgramData/Chocolatey/bin:/c/Strawberry/c/bin:$PATH"
fi

# Check for zip - on Windows it might be zip.exe
# Also check for iasl and nasm on Windows with where command
check_exe() {
  local tool="$1"
  if [ "$(unamer)" = "Windows" ]; then
    where "$tool" > /dev/null 2>&1
    return $?
  else
    command -v "$tool" >/dev/null 2>&1
    return $?
  fi
}

if [ "$(which git)" = "" ]; then
  echo "Missing git, please install it!"
  exit 1
fi

if ! check_exe zip; then
  echo "Missing zip, please install it!"
  exit 1
fi

if [ "$(unamer)" = "Darwin" ]; then
  if [ "$(which clang)" = "" ] || [ "$(clang -v 2>&1 | grep "no developer")" != "" ] || [ "$(git -v 2>&1 | grep "no developer")" != "" ]; then
    echo "Missing Xcode tools, please install them!"
    exit 1
  fi
fi

# Check for nasm and iasl on Windows using where command
if [ "$(unamer)" = "Windows" ]; then
  # On Windows, check if tools exist before running them
  if ! check_exe nasm; then
    echo "Missing or incompatible nasm!"
    echo "Download the latest nasm from http://www.nasm.us/pub/nasm/releasebuilds"
    echo "Current PATH: $PATH"
    exit 1
  fi
  if [ "$(nasm -v | grep Apple)" != "" ]; then
    echo "Missing or incompatible nasm!"
    exit 1
  fi
  if ! check_exe iasl; then
    echo "Missing iasl!"
    echo "Download the latest iasl from https://acpica.org/downloads"
    exit 1
  fi
else
  if [ "$(nasm -v)" = "" ] || [ "$(nasm -v | grep Apple)" != "" ]; then
    echo "Missing or incompatible nasm!"
    echo "Download the latest nasm from http://www.nasm.us/pub/nasm/releasebuilds"
    echo "Current PATH: $PATH -- $(which nasm)"
    # On Darwin we can install prebuilt nasm. On Linux let users handle it.
    if [ "$(unamer)" = "Darwin" ]; then
      prompt "Install last tested version automatically?"
    else
      exit 1
    fi
    pushd /tmp >/dev/null || exit 1
    rm -rf nasm-mac64.zip
    curl -OL "https://github.com/acidanthera/ocbuild/raw/master/external/nasm-mac64.zip" || exit 1
    nasmzip=$(cat nasm-mac64.zip)
    rm -rf nasm-*
    curl -OL -g "https://github.com/acidanthera/ocbuild/raw/master/external/${nasmzip}" || exit 1
    unzip -q "${nasmzip}" nasm*/nasm nasm*/ndisasm || exit 1
    sudo mkdir -p /usr/local/bin || exit 1
    sudo mv nasm*/nasm /usr/local/bin/ || exit 1
    sudo mv nasm*/ndisasm /usr/local/bin/ || exit 1
    rm -rf "${nasmzip}" nasm-*
    popd >/dev/null || exit 1
  fi

  if [ "$(iasl -v)" = "" ]; then
    echo "Missing iasl!"
    echo "Download the latest iasl from https://acpica.org/downloads"
    # On Darwin we can install prebuilt iasl. On Linux let users handle it.
    if [ "$(unamer)" = "Darwin" ]; then
      prompt "Install last tested version automatically?"
    else
      exit 1
    fi
    pushd /tmp >/dev/null || exit 1
    rm -rf iasl-macosx.zip
    curl -OL "https://github.com/acidanthera/ocbuild/raw/master/external/iasl-macosx.zip" || exit 1
    iaslzip=$(cat iasl-macosx.zip)
    rm -rf iasl
    curl -OL -g "https://github.com/acidanthera/ocbuild/raw/master/external/${iaslzip}" || exit 1
    unzip -q "${iaslzip}" iasl || exit 1
    sudo mkdir -p /usr/local/bin || exit 1
    sudo mv iasl /usr/local/bin/ || exit 1
    rm -rf "${iaslzip}" iasl
    popd >/dev/null || exit 1
  fi
fi

# On Darwin we need mtoc. Only for XCODE5, but do not care for now.
if [ "$(unamer)" = "Darwin" ]; then
  valid_mtoc=false
else
  valid_mtoc=true
fi

MTOC_LATEST_VERSION="1.0.3"

if [ "$(which mtoc)" != "" ]; then
  mtoc_version=$(mtoc --version)
  if [ "${mtoc_version}" = "${MTOC_LATEST_VERSION}" ]; then
    valid_mtoc=true
  elif [ "${IGNORE_MTOC_VERSION}" = "1" ]; then
    echo "Forcing the use of UNKNOWN mtoc version due to IGNORE_MTOC_VERSION=1"
    valid_mtoc=true
  else
    echo "Found incompatible mtoc installed to $(which mtoc)!"
    echo "Expected version: ${MTOC_LATEST_VERSION}"
    echo "Found version:    ${mtoc_version}"
    echo "Hint: Reinstall this mtoc or use IGNORE_MTOC_VERSION=1 at your own risk."
  fi
fi

if ! $valid_mtoc; then
  echo "Missing or incompatible mtoc!"
  echo "To build mtoc follow: https://github.com/acidanthera/ocmtoc"
  prompt "Install prebuilt mtoc automatically?"
  pushd /tmp >/dev/null || exit 1
  rm -f mtoc ocmtoc-${MTOC_LATEST_VERSION}-RELEASE.zip
  curl -OL -g "https://github.com/acidanthera/ocmtoc/releases/download/${MTOC_LATEST_VERSION}/ocmtoc-${MTOC_LATEST_VERSION}-RELEASE.zip" || exit 1
  unzip -q "ocmtoc-${MTOC_LATEST_VERSION}-RELEASE.zip" mtoc || exit 1
  sudo mkdir -p /usr/local/bin || exit 1
  sudo rm -f /usr/local/bin/mtoc /usr/local/bin/mtoc.NEW || exit 1
  sudo cp mtoc /usr/local/bin/mtoc || exit 1
  popd >/dev/null || exit 1

  mtoc_version=$(mtoc --version)
  if [ "${mtoc_version}" != "${MTOC_LATEST_VERSION}" ]; then
    echo "Failed to install a compatible version of mtoc!"
    echo "Expected version: ${MTOC_LATEST_VERSION}"
    echo "Found version:    ${mtoc_version}"
    exit 1
  fi
fi

if [ "$RELPKG" = "" ]; then
  RELPKG="$SELFPKG"
fi

if [ -n "$ARCHS" ] && [ "$(is_array ARCHS)" = "0" ]; then
  IFS=', ' read -r -a ARCHS <<< "$ARCHS"
fi

if [ -n "$ARCHS_EXT" ] && [ "$(is_array ARCHS_EXT)" = "0" ]; then
  IFS=', ' read -r -a ARCHS_EXT <<< "$ARCHS_EXT"
fi

if [ -n "$TOOLCHAINS" ] && [ "$(is_array TOOLCHAINS)" = "0" ]; then
  IFS=', ' read -r -a TOOLCHAINS <<< "$TOOLCHAINS"
fi

if [ -n "$TARGETS" ] && [ "$(is_array TARGETS)" = "0" ]; then
  IFS=', ' read -r -a TARGETS <<< "$TARGETS"
fi

if [ -n "$RTARGETS" ] && [ "$(is_array RTARGETS)" = "0" ]; then
  IFS=', ' read -r -a RTARGETS <<< "$RTARGETS"
fi

if [ -n "$BUILD_ARGUMENTS" ] && [ "$(is_array BUILD_ARGUMENTS)" = "0" ]; then
  IFS=', ' read -r -a BUILD_ARGUMENTS <<< "$BUILD_ARGUMENTS"
fi

if [ "${ARCHS[*]}" = "" ]; then
  ARCHS=('X64')
fi

if [ "${TOOLCHAINS[*]}" = "" ]; then
  if [ "$(unamer)" = "Darwin" ]; then
    TOOLCHAINS=('XCODE5')
  elif [ "$(unamer)" = "Windows" ]; then
    TOOLCHAINS=('VS2022')
  else
    TOOLCHAINS=('CLANGPDB' 'GCC')
  fi
fi

if [ "${TARGETS[*]}" = "" ]; then
  TARGETS=('DEBUG' 'RELEASE' 'NOOPT')
elif [ "${RTARGETS[*]}" = "" ]; then
  RTARGETS=("${TARGETS[@]}")
fi

if [ "${RTARGETS[*]}" = "" ]; then
  RTARGETS=('DEBUG' 'RELEASE')
fi

if [ "${BUILD_ARGUMENTS[*]}" = "" ]; then
  BUILD_ARGUMENTS=()
fi

if [ -z "${SKIP_TESTS}" ]; then
  SKIP_TESTS=0
fi
if [ -z "${SKIP_BUILD}" ]; then
  SKIP_BUILD=0
fi
if [ -z "${SKIP_PACKAGE}" ]; then
  SKIP_PACKAGE=0
fi

MODE=""

while true; do
  if [ "$1" == "--skip-tests" ]; then
    SKIP_TESTS=1
    shift
  elif [ "$1" == "--skip-build" ]; then
    SKIP_BUILD=1
    shift
  elif [ "$1" == "--skip-package" ]; then
    SKIP_PACKAGE=1
    shift
  elif [ "$1" == "--build-extra" ]; then
    shift
    BUILD_STRING="$1"
    # shellcheck disable=SC2206
    BUILD_ARGUMENTS+=($BUILD_STRING )
    shift
  else
    break
  fi
done

if [ "$1" != "" ]; then
  MODE="$1"
  shift
fi

echo "Primary toolchain ${TOOLCHAINS[0]} and arch ${ARCHS[0]}"

if [ ! -d "Binaries" ]; then
  mkdir Binaries || exit 1
fi

if [ "$NEW_BUILDSYSTEM" != "1" ]; then
  if [ ! -f UDK/UDK.ready ]; then
    rm -rf UDK

    if [ "$(unamer)" != "Windows" ]; then
      sym=$(find . -not -type d -not -path "./coreboot/*" -exec file "{}" ";" | grep CRLF)
      if [ "${sym}" != "" ]; then
        echo "Error: the following files in the repository have CRLF line endings:"
        echo "$sym"
        exit 1
      fi
    fi
  fi
fi

if [ "$NEW_BUILDSYSTEM" != "1" ]; then
  if [ "$OFFLINE_MODE" != "1" ]; then
    updaterepo "https://github.com/dstatstrussia/audk" UDK master || exit 1
  else
    echo "Working in offline mode. Skip UDK update"
  fi
fi
cd UDK || exit 1
HASH=$(git rev-parse '@{upstream}')

if [ "$DISCARD_PACKAGES" != "" ]; then
  for package_to_discard in "${DISCARD_PACKAGES[@]}" ; do
    if [ -d "${package_to_discard}" ]; then
      rm -rf "${package_to_discard}"
    fi
  done
fi

if [ "$NEW_BUILDSYSTEM" != "1" ]; then
  if [ -d ../Patches ]; then
    if [ ! -f patches.ready ]; then
      setcommitauthor
      for i in ../Patches/* ; do
        git apply --ignore-whitespace "$i" || exit 1
        git add .
        git commit -m "Applied patch $i" || exit 1
      done
      touch patches.ready
    fi
  fi
fi

deps="${#DEPNAMES[@]}"
for (( i=0; i<deps; i++ )) ; do
  echo "Updating ${DEPNAMES[$i]}"
  if [ "$OFFLINE_MODE" != "1" ]; then
    updaterepo "${DEPURLS[$i]}" "${DEPNAMES[$i]}" "${DEPBRANCHES[$i]}" || exit 1
  else
    echo "Working in offline mode. Skip ${DEPNAMES[$i]} update"
  fi

done

if [ "$NEW_BUILDSYSTEM" != "1" ]; then
  if [ ! -e "${SELFPKG_DIR}" ]; then
    symlink .. "${SELFPKG_DIR}" || exit 1
  fi
fi

mkdir -p MdePkg/Include/Intel/IndustryStandard || exit 1
{
  echo '// Host compat: define missing UEFI types for MicroTool host build'
  echo '#ifndef _OC_HOST_COMPAT_'
  echo '#define _OC_HOST_COMPAT_'
  echo '#ifndef EFI_AP_PROCEDURE'
  echo 'typedef VOID (EFIAPI *EFI_AP_PROCEDURE)(IN OUT VOID *Buffer);'
  echo '#endif'
  echo 'typedef EFI_AP_PROCEDURE EFI_MP_SERVICES_STARTUP_ALL_APS;'
  echo 'typedef EFI_AP_PROCEDURE EFI_MP_SERVICES_STARTUP_THIS_AP;'
  echo '#endif'
  if [ -f ../Include/Intel/IndustryStandard/AppleIntelCpuInfo.h ]; then
    cat ../Include/Intel/IndustryStandard/AppleIntelCpuInfo.h
  elif [ -f OpenCorePkg/Include/Intel/IndustryStandard/AppleIntelCpuInfo.h ]; then
    cat OpenCorePkg/Include/Intel/IndustryStandard/AppleIntelCpuInfo.h
  fi
} > MdePkg/Include/Intel/IndustryStandard/AppleIntelCpuInfo.h || exit 1
if [ -f ../Include/Apple/IndustryStandard/AppleIntelCpuInfo.h ]; then
  cp -f ../Include/Apple/IndustryStandard/AppleIntelCpuInfo.h MdePkg/Include/Intel/IndustryStandard/ || exit 1
elif [ -f OpenCorePkg/Include/Apple/IndustryStandard/AppleIntelCpuInfo.h ]; then
  cp -f OpenCorePkg/Include/Apple/IndustryStandard/AppleIntelCpuInfo.h MdePkg/Include/Intel/IndustryStandard/ || exit 1
fi
mkdir -p MdePkg/Include/Apple/IndustryStandard || exit 1
if [ -f ../Include/Apple/IndustryStandard/AppleIntelCpuInfo.h ]; then
  cp -f ../Include/Apple/IndustryStandard/AppleIntelCpuInfo.h MdePkg/Include/Apple/IndustryStandard/ || exit 1
elif [ -f OpenCorePkg/Include/Apple/IndustryStandard/AppleIntelCpuInfo.h ]; then
  cp -f OpenCorePkg/Include/Apple/IndustryStandard/AppleIntelCpuInfo.h MdePkg/Include/Apple/IndustryStandard/ || exit 1
fi

# Create Register/Cpuid.h wrapper for OpenCorePkg compatibility
mkdir -p MdePkg/Include/Register || exit 1
cat > MdePkg/Include/Register/Cpuid.h << 'CPUIDEOF'
#ifndef REGISTER_CPUID_H
#define REGISTER_CPUID_H
#if defined (MDE_CPU_IA32) || defined (MDE_CPU_X64)
#include <Register/Intel/Cpuid.h>
#endif
#endif
CPUIDEOF

. ./edksetup.sh || exit 1

# dstatstrussia/audk fork is missing EFI_AP_PROCEDURE types.
# Inject into both UefiSpec.h (duet) and PiMultiPhase.h (OpenCore firmware).
# Skip if types already exist (may be present in newer audk revisions).
if ! grep -q 'EFI_AP_PROCEDURE' MdePkg/Include/Uefi/UefiSpec.h 2>/dev/null; then
for f in MdePkg/Include/Uefi/UefiSpec.h MdePkg/Include/Pi/PiMultiPhase.h; do
  if [ -f "$f" ]; then
    LAST_ENDIF=$(grep -n '^#endif' "$f" | tail -1 | cut -d: -f1)
  sed -i.bak "${LAST_ENDIF}i\\
// Added by OC build system for host/duet compatibility\\
#ifndef _OC_EFI_MP_TYPES_DEFINED_\\
#ifndef EFI_AP_PROCEDURE\\
typedef VOID (EFIAPI *EFI_AP_PROCEDURE)(IN OUT VOID *Buffer);\\
#endif\\
typedef struct _EFI_MP_SERVICES_PROTOCOL EFI_MP_SERVICES_PROTOCOL;\\
typedef EFI_STATUS (EFIAPI *EFI_MP_SERVICES_STARTUP_ALL_APS)(\\
  IN EFI_MP_SERVICES_PROTOCOL *This,\\
  IN EFI_AP_PROCEDURE Procedure,\\
  IN BOOLEAN SingleThread,\\
  IN EFI_EVENT WaitEvent OPTIONAL,\\
  IN UINTN TimeOutInMicroSecsOns,\\
  IN VOID *ProcedureArgument OPTIONAL,\\
  OUT UINTN **FailedCpuList OPTIONAL);\\
typedef EFI_STATUS (EFIAPI *EFI_MP_SERVICES_STARTUP_THIS_AP)(\\
  IN EFI_MP_SERVICES_PROTOCOL *This,\\
  IN EFI_AP_PROCEDURE Procedure,\\
  IN UINTN ProcessorNumber,\\
  IN EFI_EVENT WaitEvent OPTIONAL,\\
  IN UINTN TimeOutInMicroSecsOns,\\
  IN VOID *ProcedureArgument OPTIONAL,\\
  OUT BOOLEAN *Finished OPTIONAL);\\
#endif\\
" "$f"
    rm -f "${f}.bak"
  fi
done
fi

if [ "$(unamer)" = "Windows" ]; then
   # Configure Visual Studio environment. Requires:
   # 1. choco install vswhere microsoft-build-tools visualcpp-build-tools nasm zip
   # 2. iasl in PATH for MdeModulePkg
   tools="${EDK_TOOLS_PATH}"
   tools="${tools//\//\\}"
   # For Travis CI
   tools="${tools/\\c\\/C:\\}"
   # For GitHub Actions
   tools="${tools/\\d\\/D:\\}"
   echo "Expanded EDK_TOOLS_PATH from ${EDK_TOOLS_PATH} to ${tools}"
   export EDK_TOOLS_PATH="${tools}"
   export BASE_TOOLS_PATH="${tools}"
   VS2022_BUILDTOOLS=$(vswhere -latest -version '[16.0,)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
   VS2022_BASEPREFIX="${VS2022_BUILDTOOLS}\\VC\\Tools\\MSVC\\"
   # Intended to use ls here to get first entry.
   # REF: https://github.com/koalaman/shellcheck/wiki/SC2012
   # shellcheck disable=SC2012
   cd "${VS2022_BASEPREFIX}" || exit 1
   # Incorrect diagnostic due to action.
   # REF: https://github.com/koalaman/shellcheck/wiki/SC2035
   # shellcheck disable=SC2035
   VS2022_DIR="$(find * -maxdepth 0 -type d -print -quit)"
   if [ "${VS2022_DIR}" = "" ]; then
     echo "No VS2022 MSVC compiler"
     exit 1
   fi
   cd - || exit 1
   export VS2022_PREFIX="${VS2022_BASEPREFIX}${VS2022_DIR}\\"
   WINSDK_BASE="/c/Program Files (x86)/Windows Kits/10/bin"
   WINSDK_VERSION=""
   if [ -d "${WINSDK_BASE}" ]; then
     for dir in "${WINSDK_BASE}"/*/; do
       if [ -f "${dir}x86/rc.exe" ]; then
         WINSDK_PATH_FOR_RC_EXE="${dir}x86"
         WINSDK_PATH_FOR_RC_EXE="${WINSDK_PATH_FOR_RC_EXE//\//\\}"
WINSDK_PATH_FOR_RC_EXE="${WINSDK_PATH_FOR_RC_EXE/\\c\\/C:\\}"
          WINSDK_VERSION="${dir##*/}"
          break
        fi
      done
    fi
    if [ "${WINSDK_PATH_FOR_RC_EXE}" != "" ]; then
      export WINSDK_PATH_FOR_RC_EXE
    else
      echo "Failed to find rc.exe"
      exit 1
    fi
    # Store WINSDK_VERSION for later use in include paths
    export WINSDK_VERSION
    BASE_TOOLS="$(pwd)/BaseTools"
    export PATH="${BASE_TOOLS}/Bin/Win32:${BASE_TOOLS}/BinWrappers/WindowsLike:$PATH"
    # Extract header paths for cl.exe to work.
    # Note: distutils.msvc9compiler was removed in Python 3.12, use VsDevCmd.bat instead
    if command -v powershell >/dev/null 2>&1; then
      ps_env_file=$(mktemp)
      # Check VS2022_BUILDTOOLS is set before running PowerShell
      if [ -n "$VS2022_BUILDTOOLS" ] && [ -f "${ROOTDIR}/Utilities/get_vs_env.ps1" ]; then
        powershell -NoProfile -File "${ROOTDIR}/Utilities/get_vs_env.ps1" -vsPath "$VS2022_BUILDTOOLS" -outFile "$ps_env_file" 2>/dev/null || true
      fi
if [ -s "$ps_env_file" ]; then
          while IFS= read -r line; do
            # Strip carriage returns from PowerShell output (Windows line endings)
            line="$(printf '%s' "$line" | tr -d '\r')"
            [ -z "$line" ] && continue
            var="${line%%=*}"
            val="${line#*=}"
            if [ -n "$var" ]; then
              if [ "$var" = "PATH" ]; then
                # PowerShell outputs Unix-style PATH (colon-separated, forward slashes)
                # Prepend MSVC paths to ensure they take precedence over other tools
                export PATH="${val}:${PATH}"
              elif [ "$var" = "CL" ]; then
                # CL from PowerShell may contain paths with spaces (breaks MSVC)
                true
              else
                printf -v "$var" '%s' "$val"
                # shellcheck disable=SC2163
                export "${var?}"
              fi
            fi
          done < "$ps_env_file"
          rm -f "$ps_env_file"
          # Verify PATH was set correctly
          if [[ "$PATH" == *"/usr/bin"* ]] && [[ "$PATH" != *"Visual Studio"* ]] && [[ "$PATH" != *"Windows Kits"* ]]; then
            echo "Warning: PowerShell PATH not applied correctly, falling back to manual PATH setup"
          fi
        else
        # Fallback: use VS2022_PREFIX directly if PowerShell failed
        if [ -n "$VS2022_PREFIX" ]; then
          # Convert VS2022_PREFIX to Git Bash path for MSVC bin
          vsMSVCpath="${VS2022_PREFIX//\//}"
          vsMSVCbin=$(echo "$vsMSVCpath" | sed 's|C:|/c|' | sed 's|/VC/Tools/MSVC/[0-9]*\.[0-9]*[^/]*/|/bin/Hostx64/x64/|' )
          export PATH="/c/Program Files (x86)/Windows Kits/10/bin/x86:${vsMSVCbin}:${PATH}"
          # Also construct INCLUDE and LIB for stdint.h and other headers
          vsMSVCinc="/c/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/${VS2022_DIR}/include"
          winSdkUCRT="C:\\Program Files (x86)\\Windows Kits\\10\\Include\\${WINSDK_VERSION}\\ucrt"
          winSdkLib="C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\${WINSDK_VERSION}\\um\\x64"
          winSdkUCRTLib="C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\${WINSDK_VERSION}\\ucrt\\x64"
          export INCLUDE="${vsMSVCinc};${winSdkUCRT}"
          export LIB="${winSdkLib};${winSdkUCRTLib}"
          # CL prepends to command line - add /WX- to disable warnings as errors and C4311/C4312/C4267/C4244
          if [ -z "${CL}" ]; then
            export CL="/WX- /wd4311 /wd4312 /wd4267 /wd4244"
          else
            export CL="${CL} /WX- /wd4311 /wd4312 /wd4267 /wd4244"
          fi
        fi
      fi
    fi
  fi

if [ "$NEW_BUILDSYSTEM" != "1" ]; then
   if [ "$SKIP_TESTS" != "1" ]; then
echo "Testing..."
if [ "$(unamer)" = "Windows" ]; then
         echo "Running nmake for Windows (unamer=Windows)"
         cd BaseTools || exit 1
         # Ensure MSVC tools take precedence over Git Bash /usr/bin tools for nmake
         # VS2022_PREFIX has format C:\...\\ so strip trailing backslash and convert
         MSVC_ROOT=$(echo "${VS2022_PREFIX}" | sed 's|\\\+$||' | sed 's|\\|/|g' | sed 's|^C:|^/c|' | sed 's|^D:|^/d|')
         # Try both x86 and x64 host paths (case-insensitive)
         MSVC_BIN=""
         for bin_path in "bin/Hostx64/x64" "bin/HostX64/x64" "bin/Hostx86/x86" "bin/HostX86/x86"; do
           if [ -d "${MSVC_ROOT}/${bin_path}" ]; then
             MSVC_BIN="${MSVC_ROOT}/${bin_path}"
             break
           fi
         done
# Also add Windows Kits x86 bin path for link.exe
          WINSDK_BIN="/c/Program Files (x86)/Windows Kits/10/bin/${WINSDK_VERSION}/x86"
          if [ -n "$MSVC_BIN" ] && [ -d "$WINSDK_BIN" ]; then
            export PATH="${MSVC_BIN}:${WINSDK_BIN}:${PATH}"
          elif [ -n "$MSVC_BIN" ]; then
            export PATH="${MSVC_BIN}:${PATH}"
          fi
          # Ensure CL is set to disable warnings-as-errors
          if [ -z "${CL}" ]; then
            export CL="/WX- /wd4311 /wd4312 /wd4267 /wd4244"
          fi
         nmake        || exit 1
        cd ..        || exit 1
      else
      make -C BaseTools -j || exit 1
    fi
    touch UDK.ready
  fi
fi

if [ "$SKIP_BUILD" != "1" ]; then
  echo "Building..."
  for i in "${!ARCHS[@]}" ; do
    for toolchain in "${TOOLCHAINS[@]}" ; do
      for target in "${TARGETS[@]}" ; do
        if [ "$MODE" = "" ] || [ "$MODE" = "$target" ]; then
          if [ "${ARCHS_EXT[i]}" == "" ]; then
            echo "Building ${SELFPKG_DIR}/${SELFPKG}.dsc for ${ARCHS[i]} in $target with ${toolchain} and flags ${BUILD_ARGUMENTS[*]} ..."
            buildme -a "${ARCHS[i]}" -b "$target" -t "${toolchain}" -p "${SELFPKG_DIR}/${SELFPKG}.dsc" "${BUILD_ARGUMENTS[@]}" || abortbuild
          else
            echo "Building ${SELFPKG_DIR}/${SELFPKG}.dsc for ${ARCHS[i]} with extra arch ${ARCHS_EXT[i]} in $target with ${toolchain} and flags ${BUILD_ARGUMENTS[*]} ..."
            buildme -a "${ARCHS_EXT[i]}" -a "${ARCHS[i]}" -b "$target" -t "${toolchain}" -p "${SELFPKG_DIR}/${SELFPKG}.dsc" "${BUILD_ARGUMENTS[@]}" || abortbuild
          fi
          echo " - OK"
        fi
      done
    done
  done
fi

cd .. || exit 1

if [ "$(type -t package)" = "function" ]; then
  if [ "$SKIP_PACKAGE" != "1" ]; then
    echo "Packaging..."
    if [ "$NO_ARCHIVES" != "1" ]; then
      rm -f Binaries/*.zip
    fi
    for rtarget in "${RTARGETS[@]}" ; do
      for toolchain in "${TOOLCHAINS[@]}" ; do
        if [ "$PACKAGE" = "" ] || [ "$PACKAGE" = "$rtarget" ]; then
          if [ "${#TOOLCHAINS[@]}" -eq 1 ]; then
            name="${rtarget}"
          else
            name="${toolchain}-${rtarget}"
          fi
          package "UDK/Build/${RELPKG}/${rtarget}_${toolchain}/${ARCHS[0]}" "${name}" "${HASH}" || exit 1
          if [ "$NO_ARCHIVES" != "1" ]; then
            cp "UDK/Build/${RELPKG}/${rtarget}_${toolchain}/${ARCHS[0]}"/*.zip Binaries || echo skipping
          fi
        fi
      done
    done
  fi
fi
