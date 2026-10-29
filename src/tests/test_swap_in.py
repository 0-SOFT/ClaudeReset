import subprocess
import time

from claude_reset import strict_guard as guard


def running_copy(tmp_path, name='app.exe'):
    program = tmp_path / name
    program.write_bytes(open(r'C:\Windows\System32\ping.exe', 'rb').read())
    return program, subprocess.Popen([str(program), '-n', '40', '127.0.0.1'], stdout=subprocess.DEVNULL, creationflags=0x08000000)


def test_a_running_program_can_be_replaced_by_renaming_it_aside(tmp_path):
    program, process = running_copy(tmp_path)
    try:
        time.sleep(.5)
        new = tmp_path / 'app.exe.new'
        new.write_bytes(b'NEW BYTES')
        guard.swap_in(new, program)
        assert program.read_bytes() == b'NEW BYTES' and not new.exists()
        asides = list(tmp_path.glob('*' + guard.ASIDE + '*'))
        assert len(asides) == 1 and process.poll() is None            # the old process keeps running from the renamed file
        guard.clear_asides(tmp_path)
        assert len(list(tmp_path.glob('*' + guard.ASIDE + '*'))) == 1  # still running, so it cannot be deleted yet
    finally:
        process.kill()
        process.wait()
    guard.clear_asides(tmp_path)
    assert list(tmp_path.glob('*' + guard.ASIDE + '*')) == []


def test_a_free_file_is_replaced_without_leaving_an_aside(tmp_path):
    target = tmp_path / 'file.exe'
    target.write_bytes(b'old')
    new = tmp_path / 'file.exe.new'
    new.write_bytes(b'new')
    guard.swap_in(new, target)
    assert target.read_bytes() == b'new' and list(tmp_path.glob('*' + guard.ASIDE + '*')) == []


def test_remove_file_renames_a_running_program_instead_of_failing(tmp_path):
    program, process = running_copy(tmp_path)
    try:
        time.sleep(.5)
        guard.remove_file(program)
        assert not program.exists() and len(list(tmp_path.glob('*' + guard.ASIDE + '*'))) == 1
    finally:
        process.kill()
        process.wait()
    guard.remove_file(tmp_path / 'missing.exe')                       # absent is fine
