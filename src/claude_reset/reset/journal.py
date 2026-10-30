"""Read-only JBD2 v3 recovery into a bounded RAM overlay.

Format reference: kernel.org/doc/html/latest/filesystems/ext4/journal.html.
No filesystem writes, journal repair, external journals or fast commits.
"""
from __future__ import annotations

import io
import struct

from dissect.util.hash.crc32c import crc32c

from ..errors import SafetyError

__all__ = ['MAGIC', 'Overlay', 'checksum', 'recovered_filesystem', 'replay_v3']

MAGIC = 0xC03B3998
LIMIT = 64 * 1024 * 1024


def checksum(data):
    return crc32c(data) ^ 0xffffffff


class Overlay(io.RawIOBase):
    def __init__(self, source, blocks, block_size, size):
        self.source, self.blocks, self.block_size, self.size = source, blocks, block_size, size
        self.position = 0

    def readable(self):
        return True
    def seekable(self):
        return True
    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset if whence == 2 else -1
        if position < 0:
            raise SafetyError('Invalid journal overlay offset')
        self.position = position
        return position

    def read(self, size=-1):
        size = self.size - self.position if size < 0 else min(size, max(0, self.size - self.position))
        if size > 256 * 1024**2:
            raise SafetyError('Journal overlay read limit exceeded')
        result = bytearray()
        while size:
            block, offset = divmod(self.position, self.block_size)
            length = min(size, self.block_size - offset)
            data = self.blocks.get(block)
            if data is None:
                self.source.seek(block * self.block_size)
                data = self.source.read(self.block_size)
            if len(data) != self.block_size:
                raise SafetyError('Truncated filesystem block')
            result.extend(data[offset:offset + length])
            self.position += length
            size -= length
        return bytes(result)


def check_superblock(journal):
    """The journal superblock, when it is a supported JBD2 v3 superblock with a valid checksum."""
    sb = journal.sb
    if (sb.s_header.h_blocktype != 4 or sb.s_feature_incompat not in (0x10, 0x11, 0x12, 0x13)
            or sb.s_feature_compat or sb.s_feature_ro_compat or sb.s_checksum_type != 4 or sb.s_errno
            or sb.s_nr_users != 1 or sb.s_blocksize not in (1024, 2048, 4096)
            or not 0 < sb.s_first < sb.s_maxlen or sb.s_maxlen * sb.s_blocksize > LIMIT):
        raise SafetyError('Unsupported JBD2 recovery schema')
    journal.fh.seek(0)
    raw = journal.fh.read(1024)
    if len(raw) != 1024 or checksum(raw[:252] + b'\0'*4 + raw[256:]) != sb.s_checksum:
        raise SafetyError('JBD2 superblock checksum failed')
    return sb


def overlay_of(committed):
    """Block replacements of committed transactions; a later revoke cancels earlier data of that block."""
    latest_revoke = {block: index for index, (_, revoked) in enumerate(committed) for block in revoked}
    overlay = {}
    for index, (changes, _) in enumerate(committed):
        for block, data in changes.items():
            if latest_revoke.get(block, -1) < index:
                overlay[block] = data
    return overlay


class Replay:
    """One pass over a JBD2 v3 journal from its start: the committed transactions with the blocks they revoke."""
    HANDLERS = {1: 'descriptor', 5: 'revoke', 2: 'commit'}   # JBD2 block type -> method

    def __init__(self, journal, filesystem_blocks):
        self.journal, self.sb, self.filesystem_blocks = journal, journal.sb, filesystem_blocks
        self.position, self.sequence, self.consumed = self.sb.s_start, self.sb.s_sequence, 0
        self.committed, self.pending, self.revokes, self.transactions = [], {}, set(), 0

    def take(self):
        sb = self.sb
        if self.consumed >= sb.s_maxlen - sb.s_first:
            raise SafetyError('JBD2 journal has no bounded end')
        block = self.journal.read_block(self.position)
        if len(block) != sb.s_blocksize:
            raise SafetyError('Truncated JBD2 journal block')
        self.position += 1
        if self.position == sb.s_maxlen:
            self.position = sb.s_first
        self.consumed += 1
        return block

    def target(self, value):
        if not 0 <= value < self.filesystem_blocks:
            raise SafetyError('JBD2 target lies outside filesystem')
        return value

    def descriptor(self, block):
        sb = self.sb
        offset, last = 12, False
        while offset + 16 <= len(block) - 4:
            low, flags, high, expected = struct.unpack_from('>IIII', block, offset)
            offset += 16
            if flags & ~0xb or (high and not sb.s_feature_incompat & 2):
                raise SafetyError('Unsupported JBD2 block tag')
            if not flags & 2:
                # Linux may leave the legacy tag UUID all-zero. Integrity is
                # bound to the journal UUID by the v3 descriptor/data CRCs.
                if offset + 16 > len(block) - 4 or block[offset:offset + 16] not in (sb.s_uuid, b'\0'*16):
                    raise SafetyError('JBD2 tag belongs to another filesystem')
                offset += 16
            data = self.take()
            if checksum(sb.s_uuid + struct.pack('>I', self.sequence) + data) != expected:
                raise SafetyError('JBD2 data checksum failed')
            if flags & 1:
                if data[:4] != b'\0'*4:
                    raise SafetyError('Invalid escaped JBD2 data block')
                data = struct.pack('>I', MAGIC) + data[4:]
            self.pending[self.target(low | (high << 32))] = data
            if flags & 8:
                last = True
                break
        if not last:
            raise SafetyError('Unterminated JBD2 descriptor')

    def revoke(self, block):
        count = struct.unpack_from('>I', block, 12)[0]
        width = 8 if self.sb.s_feature_incompat & 2 else 4
        if not 16 <= count <= len(block) - 4 or (count - 16) % width:
            raise SafetyError('Invalid JBD2 revocation table')
        self.revokes.update(self.target(int.from_bytes(block[i:i+width], 'big')) for i in range(16, count, width))

    def commit(self, block):
        if checksum(self.sb.s_uuid + block[:16] + b'\0'*4 + block[20:]) != int.from_bytes(block[16:20], 'big'):
            raise SafetyError('JBD2 commit checksum failed')
        self.committed.append((self.pending, self.revokes))
        self.pending, self.revokes = {}, set()
        self.transactions += 1
        self.sequence = (self.sequence + 1) & 0xffffffff

    def run(self):
        while True:
            block = self.take()
            magic, kind, seq = struct.unpack_from('>III', block)
            if magic != MAGIC or seq != self.sequence:
                # A transaction without a matching commit is deliberately discarded.
                break
            if kind in (1, 5):
                if checksum(self.sb.s_uuid + block[:-4] + b'\0'*4) != int.from_bytes(block[-4:], 'big'):
                    raise SafetyError('JBD2 descriptor/revoke checksum failed')
            if kind not in self.HANDLERS:
                raise SafetyError('Unknown JBD2 journal block')
            getattr(self, self.HANDLERS[kind])(block)
        return overlay_of(self.committed), self.transactions


def replay_v3(journal, filesystem_blocks):
    """Return committed block replacements; reject any unsupported/invalid checksum."""
    sb = check_superblock(journal)
    if sb.s_start == 0:
        return {}, 0
    if not sb.s_first <= sb.s_start < sb.s_maxlen:
        raise SafetyError('JBD2 start lies outside journal')
    return Replay(journal, filesystem_blocks).run()


def recovered_filesystem(fs, disk):
    from dissect.extfs import ExtFS
    disk.seek(1024)
    superblock = disk.read(1024)
    if not fs.sb.s_feature_ro_compat & 0x400 or checksum(superblock[:1020]) != int.from_bytes(superblock[1020:], 'little'):
        raise SafetyError('ext4 metadata checksum is unsupported or invalid')
    if fs.sb.s_state & 2 or fs.sb.s_feature_compat & 0x400:
        raise SafetyError('ext4 errors or fast commits require external recovery')
    if fs.block_size != fs.journal.sb.s_blocksize:
        raise SafetyError('ext4 journal block size mismatch')
    blocks, transactions = replay_v3(fs.journal, fs.block_count)
    overlay = Overlay(disk, blocks, fs.block_size, disk.size)
    recovered = ExtFS(overlay)
    if recovered.block_size != fs.block_size or recovered.block_count != fs.block_count or recovered.uuid != fs.uuid:
        raise SafetyError('Journal replay unexpectedly changed filesystem geometry')
    recovered.replayed_transactions = transactions
    recovered.replayed_blocks = len(blocks)
    return recovered
