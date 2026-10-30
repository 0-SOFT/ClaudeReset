import io
import struct
from types import SimpleNamespace
import pytest
from dissect.extfs import journal as jdb
from claude_reset.reset.journal import replay_v3, Overlay, checksum, MAGIC
from claude_reset.safeio import SafetyError

SIZE, UUID = 1024, b'0123456789abcdef'


def block(kind, seq=7):
    result = bytearray(SIZE)
    struct.pack_into('>III', result, 0, MAGIC, kind, seq)
    return result


def descriptor(data, target=10, seq=7, escaped=False):
    b = block(1, seq)
    struct.pack_into('>IIII', b, 12, target, 10 | int(escaped), 0, checksum(UUID+struct.pack('>I', seq)+data))
    struct.pack_into('>I', b, SIZE-4, checksum(UUID+b))
    return bytes(b)


def commit(seq=7):
    b = block(2, seq)
    struct.pack_into('>I', b, 16, checksum(UUID+b))
    return bytes(b)


def revoke(target, seq=8):
    b = block(5, seq)
    struct.pack_into('>I', b, 12, 24)
    struct.pack_into('>Q', b, 16, target)
    struct.pack_into('>I', b, SIZE-4, checksum(UUID+b))
    return bytes(b)


def journal(blocks, start=1):
    sb = bytearray(SIZE)
    # Native parser is an independent format reader for the generated fixture.
    struct.pack_into('>III', sb, 0, MAGIC, 4, 0)
    struct.pack_into('>IIIIII', sb, 12, SIZE, len(blocks)+2, 1, 7, start, 0)
    struct.pack_into('>III', sb, 36, 0, 0x13, 0)
    sb[48:64] = UUID
    struct.pack_into('>I', sb, 64, 1)
    sb[80] = 4
    struct.pack_into('>I', sb, 252, checksum(sb))
    return jdb.JDB2(io.BytesIO(sb + b''.join(blocks) + b'\0'*SIZE))


def test_committed_replay_and_overlay_do_not_write_original():
    data = b'X'*SIZE
    replacements, transactions = replay_v3(journal([descriptor(data), data, commit()]), 100)
    assert replacements == {10:data} and transactions == 1
    source = io.BytesIO(b'O'*SIZE*100)
    overlay = Overlay(source, replacements, SIZE, 100*SIZE)
    overlay.seek(10*SIZE-3)
    assert overlay.read(6) == b'OOOXXX'
    assert source.getvalue() == b'O'*SIZE*100


def test_incomplete_transaction_is_discarded():
    data = b'X'*SIZE
    assert replay_v3(journal([descriptor(data),data]), 100) == ({},0)


def test_later_revoke_prevents_replay_of_old_metadata():
    data = b'X'*SIZE
    assert replay_v3(journal([descriptor(data),data,commit(),revoke(10),commit(8)]), 100) == ({},2)


def test_later_reallocation_after_revoke_can_be_replayed():
    data, new = b'X'*SIZE, b'Y'*SIZE
    blocks = [descriptor(data),data,commit(),revoke(10),commit(8),descriptor(new,seq=9),new,commit(9)]
    assert replay_v3(journal(blocks),100) == ({10:new},3)


@pytest.mark.parametrize('index', [0,1,2])
def test_corrupt_descriptor_data_or_commit_blocks_recovery(index):
    data = b'X'*SIZE
    blocks = [descriptor(data),data,commit()]
    damaged = bytearray(blocks[index]);damaged[100] ^= 1;blocks[index] = bytes(damaged)
    with pytest.raises(SafetyError):
        replay_v3(journal(blocks),100)


def test_out_of_bounds_target_is_rejected():
    data = b'X'*SIZE
    with pytest.raises(SafetyError):
        replay_v3(journal([descriptor(data,target=100),data,commit()]),100)


def test_escaped_magic_restored_after_checksum_validation():
    data = b'\0'*4+b'X'*(SIZE-4)
    result,count = replay_v3(journal([descriptor(data,escaped=True),data,commit()]),100)
    assert result[10] == struct.pack('>I', MAGIC)+data[4:] and count==1


def test_unsupported_fast_commit_is_rejected():
    fixture = journal([])
    fixture.sb.s_feature_incompat |= 0x20
    with pytest.raises(SafetyError):
        replay_v3(fixture,100)
