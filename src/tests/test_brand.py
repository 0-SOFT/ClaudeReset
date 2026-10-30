"""Brand tokens, private fonts and anti-aliased shapes."""
import struct
import zlib

from claude_reset.ui import brand


def decode(data):
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    width, height = struct.unpack('>II', data[16:24])
    raw, pos = b'', 8
    while pos < len(data):
        size = struct.unpack('>I', data[pos:pos + 4])[0]
        tag = data[pos + 4:pos + 8]
        if tag == b'IDAT':
            raw += data[pos + 8:pos + 8 + size]
        pos += 12 + size
    rows = zlib.decompress(raw)
    stride = width * 4 + 1
    return width, height, lambda x, y: tuple(rows[y * stride + 1 + x * 4:y * stride + 5 + x * 4])


def test_pill_is_opaque_on_its_background_with_soft_edges():
    width, height, at = decode(brand.rounded(50, 48, 24, fill='#0e0e0e', background='#f2f1ec'))
    assert (width, height) == (50, 48)
    assert at(0, 0) == (0xf2, 0xf1, 0xec, 255)          # corner shows the background
    assert at(25, 24) == (0x0e, 0x0e, 0x0e, 255)        # centre is the fill
    edge = at(0, 24)
    assert all(0x0e < channel < 0xf2 for channel in edge[:3]) or edge[:3] == (0x0e, 0x0e, 0x0e)


def test_transparent_shapes_keep_alpha_outside():
    _, _, at = decode(brand.rounded(40, 40, 20, ring='#2e3135'))
    assert at(0, 0)[3] == 0 and at(20, 20)[3] == 0      # ghost button: only the ring is drawn
    assert at(20, 0)[3] > 0


def test_mark_has_ink_left_turquoise_right_and_an_empty_lens():
    width, height, at = decode(brand.mark(90))
    assert (width, height) == (126, 90)
    assert at(25, 45)[:3] == brand.rgb('#0e0e0e') and at(25, 45)[3] == 255
    assert at(100, 45)[:3] == brand.rgb('#92d0e3')
    assert at(63, 45)[3] == 0                             # the lens is cut out


def test_lens_checkbox_dot_and_icon_render():
    for data in (brand.lens(15), brand.checkbox(22, True, gap=10), brand.checkbox(22, False),
                 brand.dot(10, '#2f6b4f'), brand.app_icon(32)):
        width, height, at = decode(data)
        assert width > 0 and height > 0
    width, _, at = decode(brand.checkbox(22, True, gap=10, background='#f2f1ec'))
    assert width == 32 and at(30, 11) == (0xf2, 0xf1, 0xec, 255)
    _, _, at = decode(brand.app_icon(32))
    assert at(0, 0) == (0x0e, 0x0e, 0x0e, 255)


def test_fonts_load_privately_and_failures_are_skipped(tmp_path):
    for name in ('A.ttf', 'B.ttf', 'C.ttf'):
        (tmp_path / name).write_bytes(b'x')
    calls = []

    def add(path):
        calls.append(path.name)
        if path.name == 'B.ttf':
            raise OSError('broken')
        return 0 if path.name == 'C.ttf' else 1
    assert brand.register_fonts(tmp_path, add=add) == ['A.ttf']
    assert calls == ['A.ttf', 'B.ttf', 'C.ttf']


def test_bundled_fonts_and_their_licences_are_present():
    names = {p.name for p in brand.FONT_DIR.iterdir()}
    assert {'Onest.ttf', 'OnestMedium.ttf', 'OnestSemiBold.ttf', 'CormorantGaramondMedium.ttf',
            'IBMPlexMono-Medium.ttf', 'IBMPlexMono-Regular.ttf'} <= names
    assert {'OFL-Onest.txt', 'OFL-CormorantGaramond.txt', 'OFL-IBMPlexMono.txt'} <= names


def test_dpi_awareness_is_best_effort():
    calls = []
    assert brand.enable_dpi_awareness(api=lambda: calls.append('aware')) is True and calls == ['aware']

    def refuse():
        raise OSError('not supported')
    assert brand.enable_dpi_awareness(api=refuse) is False
