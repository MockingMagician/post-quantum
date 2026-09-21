'use strict';

function platform() {
  const { platform: os, arch } = process;
  if (os === 'darwin' && (arch === 'x64' || arch === 'arm64')) return `${os}-${arch}`;
  if (os === 'win32' && arch === 'x64') return 'win32-x64-msvc';
  if (os === 'linux' && (arch === 'x64' || arch === 'arm64')) {
    // Node's report identifies the linked libc without invoking a subprocess.
    // Linux builds with a glibc runtime expose this field; musl builds do not.
    const libc = process.report.getReport().header.glibcVersionRuntime ? 'gnu' : 'musl';
    return `${os}-${arch}-${libc}`;
  }
  const error = new Error(`Unsupported post-quantum native platform: ${os}/${arch}`);
  error.code = 'ERR_UNSUPPORTED_PLATFORM';
  throw error;
}

module.exports = platform;
