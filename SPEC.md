# SPEC — `mimo-backup`

Инструмент полного бэкапа и миграции среды MiMoCode (binary `mimo`) и проектов
между Linux-машинами через файл-архив (USB-диск). Go 1.26, зависимости:
`golang.org/x/crypto` (Argon2id) + транзитивный `golang.org/x/sys` — оба
официальные субрепозитории команды Go.

## 1. Команды

```
mimo-backup                  интерактивный мастер (авто-определение контекста)
mimo-backup backup  [флаги]  (b) создать архив
mimo-backup restore [флаги]  (r) восстановить архив
mimo-backup verify  [флаги]  (v) проверить архив
mimo-backup list    --src F  (l) сводка манифеста
mimo-backup secrets pack|unpack ...
```

### backup
| Флаг | Смысл |
|---|---|
| `--dest DIR` | каталог назначения (USB); обязателен |
| `--home P` | дом источника (дефолт `$HOME`) |
| `--label S` | метка `[A-Za-z0-9._-]{1,64}`, дефолт `<host>-<UTC>` |
| `--hot` / `--cold` | hot: `VACUUM INTO`-снапшот при живой mimo; cold: копия db+wal+shm, только без mimo |
| `--no-secrets` | не сохранять секреты (warn со списком пропущенного) |
| `--secret-glob G` | добавить пути (от `$HOME`) в секреты |
| `--gzip-level N` | 1..9 (дефолт 1 — быстрая запись на USB) |
| `--force` | перезаписать существующие артефакты |
| `--dry-run` | ничего не писать |
| `--stop-mimo` | остановить mimo (SIGTERM, ≤10 с) без вопросов |
| `--passphrase-file F` | пароль из файла (права 600, один завершающий `\n` стрипается) |
| `--no-passphrase` | секреты без шифрования |

### restore
| Флаг | Смысл |
|---|---|
| `--src FILE` | основной архив `.tar.gz`; обязателен |
| `--secrets FILE` | архив секретов (по умолчанию ищется рядом) |
| `--skip-secrets` | восстановить только данные (вход через `/login`) |
| `--home P` | целевой дом |
| `--force` | заменить существующее (rename → `<name>.pre-restore-<ts>`) |
| `--keep-installation-id` | восстановить `installation_id` (по умолчанию пропускается) |
| `--restore-shell-rc` | восстановить `.bashrc/.profile/.bash_profile` (по умолчанию нет) |

### verify
`--quick` (дефолт) — сверка `archive_sha256` целиком. `--full` — сверка sha256
каждого файла. `--secrets FILE` — проверить и архив секретов.

### Коды выхода
`0` ок · `1` usage/пароль не прошёл политику · `2` ошибка · `3` mimo запущена ·
`4` контрольные суммы · `5` неверный пароль / повреждённый контейнер.

## 1a. Прогресс

Во время долгих операций выводится интерактивная лента (stderr, TTY):

```
Сжатие [############------]  52%  3.1/5.9 ГиБ  1:20  45 МиБ/с  2450/328000 файлов
```

- **База процентов** — байты, записываемые в tar (без сжатия): у backup
  фактически записываемое содержимое main-архива (снапшот БД — по размеру
  снапшота; обеззараженные копии корректируют total на лету); у restore/verify —
  байты из манифеста за вычетом пропускаемых путей (только restore).
- Прогресс — **по-чанково** (256 КиБ), лента не замирает на больших файлах (БД).
- ETA — по сглаженной скорости (EWMA); первые 2 с — `~—`; `~M:SS` / `~H:MM:SS`.
- Строка усечена до ширины терминала (TIOCGWINSZ, фолбэк 80 колонок); при
  ошибке/Ctrl-C строка стирается, сообщение печатается на своей строке.
- **Без TTY**, при `--no-progress` и `--quiet` — без анимации; пишутся
  периодические строки лога (каждые 2000 файлов / 512 МиБ / 15 с) + итог.
- `--no-progress` принимается и до, и после подкоманды.

## 1b. Имена артефактов — дата всегда

Метка времени `<ГГГГММДД-ЧЧММСС>` (**локальное время**) — обязательная часть
имени: `mimo-backup-<host>-20261116-171203.tar.gz`; при `--label X` —
`mimo-backup-X-20261116-171203.tar.gz`. Все артефакты одного бэкапа
(`.tar.gz`, `-secrets.*`, `.manifest.json`) несут одну метку — сортировка по
имени = сортировка по дате. `created_at` в манифесте — в UTC.

## 2. Артефакты

- `mimo-backup-<label>.tar.gz` — основной архив
- `mimo-backup-<label>-secrets.mimosec` (с паролем) или `-secrets.tar.gz` (без)
- `mimo-backup-<label>.manifest.json` — **боковой манифест, авторитетный**
  (`files[]` с sha256, `archive_sha256`, `secrets_sha256`, `redacted_paths`, `torn[]`)

Запись всегда `*.partial` → `rename`. Без resume: обрыв = перезапуск.

## 3. Что входит в архив (in scope)

`~/.local/share/mimocode`, `~/.config/mimocode`, `~/.local/state/mimocode`,
`~/.cache/mimocode`, `~/.mimocode` (бинарник — офлайн-работа на целевой машине),
`~/.bashrc|.profile|.bash_profile` (restore только по флагу), `~/projects/*`
полностью, `~/*/.mimocode` вне projects (например `nvidia-install`),
`~/.ssh/mimo_deploy(.pub)`.

**Out of scope**: `podman-tmp/`, `~/sdk/`, остальной `~/.ssh`, `~/.chat/`.

**Transient (никогда)**: `.cron-lock`, `*.partial`, `state/locks/`,
`state/llm-server/*/server-*.json`, `storage/migration`, `.restore-journal.jsonl`,
сокеты/FIFO/устройства.

## 4. Секреты и redaction

`secret_paths` (только в архиве секретов, в основной — не попадают):
`auth.json`, `mimo-free-client`, `mimo-key-name`, `state/llm-server/*/tokens.json`,
`~/.ssh/mimo_deploy(.pub)`, **`**/.mimocode/mimocode.json*`** (любая глубина,
включая `.bak*`), **`**/.env`**, **`~/.config/mimocode/mimocode.json*`**.
`--secret-glob` добавляет пути. `~/.ssh/id_rsa` и прочее вне списка — не архивируется.

**Redacted-копии**: текстовые конфиги (`mimocode.json*`, `.env`) попадают в
основной архив с вырезанными значениями (`***REDACTED***`) — чтобы проекты не
остались без конфигурации при restore без секретов. Алгоритм: замена значений по
ключам (`apiKey`, `token`, `authorization`, `password`, `secret`, …) + контент-regex
(`Bearer …`, `sk-…`). При восстановлении секретов redacted-копии заменяются
полными автоматически (без `--force`).

## 5. Формат `.mimosec` (v2)

Все числа big-endian. `v1 = reserved`.

```
off  len  поле
0    8    magic "MIMOSEC1"
8    2    version u16 = 2
10   2    kdf_id u16 = 2 (Argon2id)
12   4    m_cost u32 (KiB, дефолт 65536 = 64 МиБ)
16   4    t_cost u32 (дефолт 3)
20   4    p_cost u32 (дефолт 1)
24   4    salt_len u32 = 32 (фиксировано)
28   32   salt (crypto/rand)
60   12   nonce (crypto/rand)
72   …    ct||tag = AES-256-GCM(key, nonce, payload); AAD = header[0:72]
```

Ключ = `argon2.IDKey(password, salt, t, m, p, 32)`.

**Границы при Open (до Argon2id)**: `salt_len != 32`, `m_cost > 1 GiB`,
`t_cost > 16`, `p_cost > 16`, неизвестные version/kdf_id → отказ (защита от
cost-бомбы в недоверенном контейнере).

**Пароль**: `A–Z a–z 0–9`, мин. 5, макс. 1024. При создании — двойной ввод с
проверкой совпадения. Подсказка: `пароль [мин. 5, лучше 12+ — не перебираемый]`.

## 6. Алгоритмы

**Backup** (один проход, hash-while-write): discover → классификация →
гейт mimo → statfs → снапшот БД → архив секретов → основной tar.gz потоком
(`io.TeeReader` в sha256; short-read → zero-pad + `torn[]`) → манифест последним
entry (RAM-буфер ~60 МБ на 328k файлов; tar требует известный Size) → fsync →
rename → sidecar.

**Снапшот БД**: `mimo db "VACUUM INTO '<path>'"` (путь SQL-экранируется:
удвоение `'`, запрет `;` и управляющих символов). Фолбэк — холодная копия
`db+wal+shm` (только без mimo). Манифест фиксирует `method`.

**Restore**: гейт mimo → чтение sidecar (без него — двухпроходный fallback с
предупреждением; молчаливое извлечение без сверки запрещено) → конфликты
(`--force` → rename в `.pre-restore-<ts>`) → потоковое извлечение со сверкой
sha256 на лету → журнал `.restore-journal.jsonl` (append+fsync, удаляется при
успехе) → секреты (отдельный шаг; redacted-копии заменяются без `--force`).

**При живой mimo** (мастер): «mimo работает и мешает…» →
[1] Остановить mimo и продолжить · [2] Выйти и остановить самому ·
(backup) [3] Продолжить с `--hot`. Неинтерактивно — exit 3; `--stop-mimo` —
остановить без вопросов.

## 7. Threat model

Что защищает `.mimosec`: файловые секреты (auth.json, ключи, токены конфигов).
Что НЕ защищено: токены внутри `mimocode.db` (таблицы `account`,
`control_account`, `session_share`) — основной архив остаётся чувствительным;
файте архив как конфиденциальный. Обнуление буферов пароля/ключа — best-effort
(GC в Go не гарантирует). Перебор пароля в 5 знаков (~30 бит) на хорошем GPU —
дни–недели; длина пароля — единственная реальная граница.

## 8. Recovery после сбоя

- Обрыв записи: `*.partial` не промотан — удалите его, повторите бэкап.
- Сбой restore: файл `.restore-journal.jsonl` показывает извлечённое;
  `.pre-restore-*` — safety-копии; сообщение exit 4 перечисляет следующие шаги.
- Проверка: `verify --quick` (быстро) / `verify --full` (после копирования).
