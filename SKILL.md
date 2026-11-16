---
name: mimo-backup
description: Use when the user wants to back up, migrate, restore, or verify a MiMoCode environment (sessions, memory, settings, skills, projects) between Linux machines via an archive/USB disk. Trigger on 'mimo-backup', 'перенести mimocode на другой компьютер', 'бэкап mimocode', 'восстановить архив mimocode', 'migrate mimo data'.
---

# mimo-backup

CLI для полного бэкапа/восстановления среды MiMoCode. Бинарник: `mimo-backup`
(синонимы команд: `b`/`r`/`v`/`l`/`s`). Полная спека: `SPEC.md` в корне проекта.

## Типовые операции

```bash
# Мастер без аргументов — сам определяет контекст и задаёт вопросы
mimo-backup

# Бэкап на USB (секреты с паролем — мастер спросит)
mimo-backup backup --dest /media/chubuk/USB

# Бэкап без секретов (на новой машине — /login)
mimo-backup backup --dest /media/chubuk/USB --no-secrets

# Проверка архива после копирования
mimo-backup verify --src /media/chubuk/USB/mimo-backup-X.tar.gz

# Восстановление (данные + секреты автоматически найдутся рядом)
mimo-backup restore --src /media/chubuk/USB/mimo-backup-X.tar.gz

# Только данные, секреты потом
mimo-backup restore --src ... --skip-secrets
```

## Важные правила

- Лента прогресса 0–100% с ETA (байты в tar); без TTY / `--no-progress` / `--quiet` —
  обычные периодические строки лога.
- Имена архивов всегда содержат дату: `mimo-backup-<метка>-<ГГГГММДД-ЧЧММСС>…`;
  свой `--label` дописывается перед датой.
- При живой `mimo` backup/restore требуют остановки: мастер предложит
  «Остановить mimo и продолжить / Выйти»; из скриптов — `--stop-mimo` или
  `--hot` (только backup).
- Пароль секретов: `A–Z a–z 0–9`, мин. 5, при создании вводится дважды.
- `restore` без секретов не оставит проекты без конфигов — в основном архиве
  лежат обеззараженные копии (`***REDACTED***`), которые при распаковке
  секретов заменяются полными автоматически.
- `installation_id` по умолчанию не восстанавливается (у каждой машины свой).
- Коды выхода: 3 = mimo запущена, 4 = контрольные суммы, 5 = пароль/контейнер.
