"""Linux root store profile: strict labels/ACLs, no reset or relabel operations."""
from contextlib import contextmanager
import os
import re
import stat
import sys

from harbor_recovery_store import Store, require

NAMES = re.compile(r'(?:controller\.lock|manager\.lock|state\.json|policy-transition\.json|'
                   r'(?:state|policy)-[0-9a-f]{32}\.pending|'
                   r'(?:intent|policy-claim)-[0-9]{20}\.json|'
                   r'(?:operator-hold|manager-hold|logger-reconcile-request|initial-arm-request)-[0-9a-f]{32}\.json)')


def label(value):
    require(isinstance(value, str) and re.fullmatch('[A-Za-z0-9_:.,-]+', value), 'STORE_CONTEXT')
    return value


class ProtectedStore(Store):
    """Production callers use uid=gid=0. Overrides are for unprivileged CI only.

    Shared parents: owner/no write/no ACL checks. Store directory/files: exact
    mode/gid/SELinux, no ACL or unknown xattrs. No filesystem mutation to repair
    metadata. New file label must be supplied by the prepared filesystem.
    """
    def __init__(self, directory, directory_context, file_context, *, uid=0, gid=0):
        require(sys.platform == 'linux', 'LINUX_PROTECTED_STORE_REQUIRED')
        super().__init__(directory, uid=uid)
        self.gid = gid
        self.directory_context, self.file_context = label(directory_context), label(file_context)

    def _attrs(self, fd, expected=None):
        attrs = set(os.listxattr(fd))
        require(not attrs & {'system.posix_acl_access', 'system.posix_acl_default'}, 'STORE_ACL_PRESENT')
        if expected is not None:
            require(attrs == {'security.selinux'}, 'STORE_UNEXPECTED_XATTR')
            current = os.getxattr(fd, 'security.selinux').rstrip(b'\0').decode('ascii')
            require(current == expected, 'STORE_CONTEXT_CHANGED')

    def _directory(self):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        try:
            for part in (None, *self.path.parts[1:]):
                if part is not None:
                    child = os.open(part, flags, dir_fd=fd)
                    os.close(fd); fd = child
                st = os.fstat(fd)
                require(st.st_uid in (0, self.uid) and not st.st_mode & 0o022, 'UNTRUSTED_STORE_PARENT')
                self._attrs(fd)
            st = os.fstat(fd)
            require(st.st_uid == self.uid and st.st_gid == self.gid and
                    stat.S_IMODE(st.st_mode) == 0o700, 'PROTECTED_STORE_DIRECTORY')
            self._attrs(fd, self.directory_context)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _file(self, name, flags):
        require(isinstance(name, str) and NAMES.fullmatch(name), 'STORE_RECORD_NAME')
        fd = super()._file(name, flags)
        try:
            st = os.fstat(fd)
            require(st.st_gid == self.gid and stat.S_IMODE(st.st_mode) == 0o600, 'PROTECTED_STORE_FILE')
            self._attrs(fd, self.file_context)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def inventory(self):
        require(self.fd is not None, 'STORE_LOCK_REQUIRED')
        names = os.listdir(self.fd)
        require(len(names) <= 4096, 'STORE_RECORD_LIMIT')
        for name in names:
            fd = self._file(name, os.O_RDONLY)
            os.close(fd)
        return {'files': len(names), 'pending': sorted(n for n in names if n.endswith('.pending'))}

    @contextmanager
    def locked(self):
        with super().locked():
            self.inventory()
            yield self

    def _new(self, name, raw):
        require(not self.inventory()['pending'], 'STORE_UNCOMMITTED_EVIDENCE')
        super()._new(name, raw)

    def save(self, state):
        require(not self.inventory()['pending'], 'STORE_UNCOMMITTED_EVIDENCE')
        super().save(state)
