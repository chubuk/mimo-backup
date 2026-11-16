# mimo-backup

[![Release](https://img.shields.io/github/v/release/chubuk/mimo-backup)](https://github.com/chubuk/mimo-backup/releases)
[![Go](https://img.shields.io/github/go-version/chubuk/mimo-backup)](https://go.dev/)

Полный бэкап и перенос среды [MiMoCode](https://github.com/mimo) + проектов между
Linux-машинами через USB-архив. Один статический бинарник без внешних рантайм-зависимостей.

## Возможности

- **Всё окружение**: сессии, память, планы, скиллы, конфиги, БД `mimocode.db`, все проекты `~/projects/*`, установка `~/.mimocode` (работа без сети)
- **Секреты отдельно**: `auth.json`, ключи, токены — в архиве секретов с опциональным паролем (Argon2id + AES-256-GCM)
- **`--encrypt`**: весь архив в один зашифрованный контейнер `.mimosec` (данные + опись + секреты)
- **Откат одной командой**: `mimo-backup rollback` возвращает систему как было до восстановления (дерево байт-в-байт)
- **Git-история настроек**: правки в `~/.config/mimocode/**` и rc-файлах видны в `history`, изменения сохраняются перед откатом
- **Проверка целостности**: sha256 каждого файла + sha256 всего архива; `verify --quick` / `--full`
- **Лента прогресса** 0–100% с ETA; имена архивов всегда содержат дату
- **Интерактивный мастер**: `mimo-backup` без аргументов сам определяет контекст

## Установка

### Linux (deb, amd64/arm64)

```bash
sudo dpkg -i mimo-backup_1.1.2_amd64.deb
```

### macOS (pkg, Apple Silicon и Intel)

Универсальный инсталлятор `mimo-backup-1.1.2-macos.pkg` из
[релиза](https://github.com/chubuk/mimo-backup/releases) — работает на
Mac с чипами M1/M2/M3 (Apple Silicon) и на Intel:

```bash
sudo installer -pkg mimo-backup-1.1.2-macos.pkg -target /
```

Либо просто положите бинарник в PATH: `mimo-backup-darwin-arm64`
(Apple Silicon) или `mimo-backup-darwin-amd64` (Intel).

### Из исходников (Linux и macOS)

```bash
go build -ldflags="-s -w -X main.version=1.1.2" -o ~/.local/bin/mimo-backup ./cmd/mimo-backup
```

## Быстрый старт

```bash
# на старой машине — просто запустите и отвечайте на вопросы:
mimo-backup

# или без вопросов (имя архива всегда содержит дату):
mimo-backup backup --dest /media/chubuk/USB
#   → mimo-backup-chubuk-20261116-171203.tar.gz

# на новой машине:
mimo-backup restore --src /media/chubuk/USB/mimo-backup-*.tar.gz
# затем: mimo → /login  (или восстановите секреты сразу)
```

## Команды

| Команда | Что делает |
|---|---|
| `mimo-backup` | интерактивный мастер (авто-определение контекста) |
| `backup` (`b`) | создать архив (`--encrypt` — весь архив в контейнер `.mimosec`) |
| `restore` (`r`) | восстановить архив (выборочно: данные / + секреты) |
| `rollback` (`rb`) | откатить последнее восстановление (`--dry-run`, `--yes`) |
| `verify` (`v`) | проверить архив (`--quick` / `--full`) |
| `list` (`l`) | сводка манифеста |
| `history` (`h`) | поколения восстановлений и история настроек (git) |
| `cleanup` (`c`) | чистка старых поколений (`--keep N`, `--all`) |
| `fix-nested` (`fn`) | починка машин, восстановленных v1.0.0 (баг с `~/home/`) |
| `secrets pack\|unpack` | тонкая работа с архивом секретов |

Если машина восстанавливалась на **v1.0.0** и данные легли в `~/home/` —
запустите `mimo-backup fix-nested --apply` (или см. [SPEC.md](SPEC.md) §10).

Полное описание форматов и флагов — [SPEC.md](SPEC.md).

## Документация

- [SPEC.md](SPEC.md) — форматы архивов, крипто-контейнер, алгоритмы, threat model
- [SKILL.md](SKILL.md) — скилл для агентов MiMoCode
- [CHANGELOG.md](CHANGELOG.md) — история изменений

## Лицензия

MIT — см. [LICENSE](LICENSE).
