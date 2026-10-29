"""Read the bundled, fixed documentation without launching external programs."""
from pathlib import Path

from .safeio import SafetyError


ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = {
    'guide': ('Руководство', 'docs/USER-GUIDE.md'),
    'limits': ('Границы и приёмка', 'docs/GUI-ACCEPTANCE.md'),
    'licenses': ('Лицензионные уведомления', 'docs/LICENSE-REVIEW-G6.md'),
}
LICENSE_DOCUMENTS = (
    'third_party/NOTICES.md',
    'third_party/licenses/defusedxml-0.7.1/LICENSE',
    'third_party/licenses/dissect.cstruct-4.7/COPYRIGHT',
    'third_party/licenses/dissect.cstruct-4.7/LICENSE',
    'third_party/licenses/dissect.extfs-3.15/COPYRIGHT',
    'third_party/licenses/dissect.extfs-3.15/LICENSE',
    'third_party/licenses/dissect.hypervisor-3.21/COPYRIGHT',
    'third_party/licenses/dissect.hypervisor-3.21/LICENSE',
    'third_party/licenses/dissect.util-3.24/COPYRIGHT',
    'third_party/licenses/dissect.util-3.24/LICENSE',
    'third_party/licenses/Sandboxie-v1.18.8/LICENSE',
    'third_party/licenses/sing-box-1.14.4/LICENSE',
    'third_party/licenses/sing-box-1.14.4/GPL-3.0.txt',
    'third_party/licenses/Onest/OFL.txt',
    'third_party/licenses/CormorantGaramond/OFL.txt',
    'third_party/licenses/IBMPlexMono/OFL.txt',
)


def localized(relative, language):
    """docs/X.md -> docs/X.en.md for an English window when that translation is bundled."""
    if language == 'en' and relative.endswith('.md'):
        english = relative[:-3] + '.en.md'
        if (ROOT / english).is_file():
            return english
    return relative


def read_document(kind: str, language: str = 'ru') -> tuple[str, str]:
    if kind not in DOCUMENTS:
        raise SafetyError('Неизвестный раздел справки.')
    title, relative = DOCUMENTS[kind]
    try:
        paths = tuple(localized(path, language) for path in (relative,) + (LICENSE_DOCUMENTS if kind == 'licenses' else ()))
        sections = []
        for path in paths:
            content = (ROOT / path).read_text(encoding='utf-8')
            if not content.strip():
                raise ValueError('empty document')
            sections.append((f'\n\n--- {path} ---\n\n' if kind == 'licenses' else '') + content)
        content = ''.join(sections)
    except (OSError, UnicodeError, ValueError):
        raise SafetyError('Справка недоступна. Проверьте комплект файлов программы.') from None
    return title, content


def check_bundle() -> tuple[str, str]:
    """Проверить читаемость всех разделов; это не проверка подлинности или лицензии."""
    rows = []
    complete = True
    for kind, (title, _) in DOCUMENTS.items():
        try:
            read_document(kind)
        except SafetyError:
            complete = False
            rows.append(f'{title}: недоступен')
        else:
            rows.append(f'{title}: доступен')
    summary = 'Справка комплектна.' if complete else 'Справка неполна. Восстановите комплект файлов программы.'
    return 'Проверка справки', '\n'.join([summary, *rows,
        'Проверены наличие, непустой текст и UTF-8. Подлинность, актуальность и право распространения не проверены.'])
