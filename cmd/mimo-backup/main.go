// Command mimo-backup backs up and migrates a MiMoCode environment
// between Linux machines via an intermediate archive (e.g. USB disk).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/chubuk/mimo-backup/internal/backup"
	"github.com/chubuk/mimo-backup/internal/env"
	"github.com/chubuk/mimo-backup/internal/restore"
	"github.com/chubuk/mimo-backup/internal/secbox"
	"github.com/chubuk/mimo-backup/internal/ui"
)

// version is stamped at build time via -ldflags "-X main.version=X.Y.Z".
var version = "1.0.0"

const (
	exitOK       = 0
	exitUsage    = 1
	exitError    = 2
	exitMimoLive = 3
	exitVerify   = 4
	exitPass     = 5
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	log := slog.Default()

	if len(args) == 0 {
		return wizard(log)
	}

	// Global flags may precede the subcommand.
	fs := flag.NewFlagSet("mimo-backup", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "подробный вывод")
	quiet := fs.Bool("quiet", false, "только ошибки")
	yes := fs.Bool("yes", false, "неинтерактивный режим")
	noProgress := fs.Bool("no-progress", false, "без ленты прогресса")
	fs.Usage = usage
	// Parse only leading flags.
	var rest []string
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		_ = fs.Parse(args[:i])
		rest = args[i:]
		break
	}
	if rest == nil {
		_ = fs.Parse(args)
		rest = nil
	}
	if *verbose {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if *quiet {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}

	if len(rest) == 0 {
		usage()
		return exitUsage
	}

	cmd, rest := rest[0], rest[1:]
	full := cmd
	switch cmd {
	case "b":
		full = "backup"
	case "r":
		full = "restore"
	case "v":
		full = "verify"
	case "l":
		full = "list"
	case "s":
		full = "secrets"
	}

	// --quiet also silences the progress bar.
	noProg := *noProgress || *quiet

	switch full {
	case "backup":
		return cmdBackup(rest, log, *yes, noProg)
	case "restore":
		return cmdRestore(rest, log, *yes, noProg)
	case "verify":
		return cmdVerify(rest, log, noProg)
	case "list":
		return cmdList(rest)
	case "secrets":
		return cmdSecrets(rest, log, *yes)
	case "version", "--version":
		fmt.Println("mimo-backup", version)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n", cmd)
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mimo-backup — бэкап и перенос среды MiMoCode

Использование:
  mimo-backup                  интерактивный мастер
  mimo-backup backup  [флаги]  создать архив (b)
  mimo-backup restore [флаги]  восстановить архив (r)
  mimo-backup verify  [флаги]  проверить архив (v)
  mimo-backup list    --src F  что в архиве (l)
  mimo-backup secrets pack|unpack ...

Флаги backup:  --dest DIR --home P --label S --hot|--cold --no-secrets
               --secret-glob G --gzip-level N --force --dry-run --stop-mimo
Флаги restore: --src FILE [--secrets FILE] [--skip-secrets] --home P
               --force [--passphrase-file F] [--no-passphrase]
               --keep-installation-id --restore-shell-rc --dry-run --stop-mimo
Флаги verify:  --src FILE [--quick|--full] [--secrets FILE]
Общие:         --verbose --quiet --yes --no-progress (без ленты прогресса)
`)
}

// ---------------------------------------------------------------------------
// backup

func cmdBackup(args []string, log *slog.Logger, yes bool, noProg bool) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dest := fs.String("dest", "", "каталог назначения (USB)")
	home := fs.String("home", os.Getenv("HOME"), "домашний каталог источника")
	label := fs.String("label", "", "метка архива [A-Za-z0-9._-]")
	hot := fs.Bool("hot", false, "работать при живой mimo (VACUUM INTO)")
	cold := fs.Bool("cold", false, "холодная копия БД (только без mimo)")
	noSecrets := fs.Bool("no-secrets", false, "не сохранять секреты")
	var globs stringList
	fs.Var(&globs, "secret-glob", "дополнительные секреты (glob от $HOME)")
	gzipLevel := fs.Int("gzip-level", 1, "уровень gzip 1..9")
	force := fs.Bool("force", false, "перезаписать существующие артефакты")
	dryRun := fs.Bool("dry-run", false, "ничего не писать")
	stopMimo := fs.Bool("stop-mimo", false, "остановить mimo без вопросов")
	passFile := fs.String("passphrase-file", "", "файл с паролем секретов")
	noPass := fs.Bool("no-passphrase", false, "без пароля (незашифрованные секреты)")
	subNoProg := fs.Bool("no-progress", false, "без ленты прогресса")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	noProg = noProg || *subNoProg
	if *dest == "" {
		fmt.Fprintln(os.Stderr, "--dest обязателен")
		return exitUsage
	}
	if !filepath.IsAbs(*dest) {
		abs, err := filepath.Abs(*dest)
		if err == nil {
			*dest = abs
		}
	}

	skipGate := os.Getenv("MIMO_BACKUP_SKIP_PROC_GATE") == "1"
	u := ui.New()
	interactive := isTerminal(os.Stdin)

	o := backup.Options{
		Dest: *dest, Home: *home, Label: *label,
		Hot: *hot, Cold: *cold, NoSecrets: *noSecrets,
		SecretGlobs: globs, GzipLevel: *gzipLevel,
		Force: *force, DryRun: *dryRun, StopMimo: *stopMimo,
		Yes: yes, Log: log, SkipProcGate: skipGate, NoProgress: noProg,
	}
	o.ConfirmStopMimo = func() (bool, bool, error) {
		if !interactive {
			return false, false, fmt.Errorf("mimo запущена; остановите её или используйте --hot (только backup)")
		}
		fmt.Fprintln(os.Stderr, "\nmimo сейчас работает и мешает созданию архива. Пока она открыта, архив может быть неполным.")
		idx, err := u.Choose("Что делаем?", []string{
			"Остановить mimo и продолжить",
			"Продолжить с --hot (снимок БД, но возможны недописанные файлы)",
			"Выйти и остановить mimo самому",
		}, 0)
		if err != nil {
			return false, false, err
		}
		switch idx {
		case 0:
			return true, false, nil
		case 1:
			return false, true, nil
		default:
			return false, false, fmt.Errorf("остановите mimo и запустите команду снова")
		}
	}
	o.AskPassphrase = func() (string, error) {
		if *noPass {
			return "", nil
		}
		if *passFile != "" {
			return readPassFile(*passFile)
		}
		if env := os.Getenv("MIMO_BACKUP_PASSPHRASE"); env != "" {
			if err := secbox.ValidatePassword(env); err != nil {
				return "", err
			}
			return env, nil
		}
		if yes {
			return "", nil // non-interactive without passphrase source: unencrypted
		}
		encrypt, err := u.Confirm("Защитить секреты паролем?", true)
		if err != nil {
			return "", err
		}
		if !encrypt {
			return "", nil
		}
		return u.ReadPasswordNew()
	}

	err := backup.Run(o)
	return mapErr(err, log)
}

// ---------------------------------------------------------------------------
// restore

func cmdRestore(args []string, log *slog.Logger, yes bool, noProg bool) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	src := fs.String("src", "", "основной архив .tar.gz")
	secrets := fs.String("secrets", "", "архив секретов (по умолчанию ищется рядом)")
	skipSecrets := fs.Bool("skip-secrets", false, "не восстанавливать секреты")
	home := fs.String("home", os.Getenv("HOME"), "целевой домашний каталог")
	force := fs.Bool("force", false, "заменить существующее (сafety-копией)")
	passFile := fs.String("passphrase-file", "", "файл с паролем")
	noPass := fs.Bool("no-passphrase", false, "секреты без пароля")
	keepID := fs.Bool("keep-installation-id", false, "восстановить installation_id")
	restoreRC := fs.Bool("restore-shell-rc", false, "восстановить .bashrc/.profile")
	dryRun := fs.Bool("dry-run", false, "ничего не писать")
	stopMimo := fs.Bool("stop-mimo", false, "остановить mimo без вопросов")
	subNoProg := fs.Bool("no-progress", false, "без ленты прогресса")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	noProg = noProg || *subNoProg
	if *src == "" {
		fmt.Fprintln(os.Stderr, "--src обязателен")
		return exitUsage
	}
	if *skipSecrets && *secrets != "" {
		log.Warn("--skip-secrets игнорирует --secrets")
		*secrets = ""
	}

	skipGate := os.Getenv("MIMO_BACKUP_SKIP_PROC_GATE") == "1"
	u := ui.New()
	interactive := isTerminal(os.Stdin)

	o := restore.Options{
		Src: *src, Secrets: *secrets, SkipSecrets: *skipSecrets,
		Home: *home, Force: *force, KeepInstID: *keepID, RestoreRC: *restoreRC,
		DryRun: *dryRun, StopMimo: *stopMimo, Yes: yes, Log: log, SkipProcGate: skipGate,
		NoProgress: noProg,
	}
	o.ConfirmStopMimo = func() (bool, error) {
		if !interactive {
			return false, fmt.Errorf("mimo запущена; остановите её и запустите команду снова")
		}
		fmt.Fprintln(os.Stderr, "\nmimo сейчас работает и мешает распаковке. Пока она открыта, восстановление может конфликтовать с ней.")
		idx, err := u.Choose("Что делаем?", []string{
			"Остановить mimo и продолжить",
			"Выйти и остановить mimo самому",
		}, 0)
		if err != nil {
			return false, err
		}
		return idx == 0, nil
	}
	o.AskPassphrase = func(encrypted bool) (string, error) {
		if *noPass {
			return "", nil
		}
		if *passFile != "" {
			return readPassFile(*passFile)
		}
		if env := os.Getenv("MIMO_BACKUP_PASSPHRASE"); env != "" {
			return env, nil
		}
		if !encrypted {
			return "", nil
		}
		return u.ReadPasswordOnce()
	}

	err := restore.Restore(o)
	return mapErr(err, log)
}

// ---------------------------------------------------------------------------
// verify / list / secrets

func cmdVerify(args []string, log *slog.Logger, noProg bool) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	src := fs.String("src", "", "архив")
	quick := fs.Bool("quick", false, "только sha256 архива (по умолчанию)")
	full := fs.Bool("full", false, "проверка всех файлов")
	secrets := fs.String("secrets", "", "проверить и архив секретов")
	subNoProg := fs.Bool("no-progress", false, "без ленты прогресса")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	noProg = noProg || *subNoProg
	if *src == "" {
		fmt.Fprintln(os.Stderr, "--src обязателен")
		return exitUsage
	}
	if !*quick && !*full {
		*quick = true
	}
	o := restore.Options{Src: *src, Secrets: *secrets, Quick: *quick, Full: *full, Log: log, NoProgress: noProg}
	err := restore.Verify(o)
	return mapErr(err, log)
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	src := fs.String("src", "", "архив")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *src == "" {
		fmt.Fprintln(os.Stderr, "--src обязателен")
		return exitUsage
	}
	if err := restore.List(restore.Options{Src: *src}); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return exitError
	}
	return exitOK
}

func cmdSecrets(args []string, log *slog.Logger, yes bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "secrets pack|unpack ...")
		return exitUsage
	}
	switch args[0] {
	case "pack":
		return cmdSecretsPack(args[1:], log, yes)
	case "unpack":
		return cmdSecretsUnpack(args[1:], log, yes)
	default:
		fmt.Fprintf(os.Stderr, "неизвестная подкоманда secrets %q\n", args[0])
		return exitUsage
	}
}

func cmdSecretsPack(args []string, log *slog.Logger, yes bool) int {
	fs := flag.NewFlagSet("secrets pack", flag.ContinueOnError)
	out := fs.String("out", "", "выходной контейнер")
	passFile := fs.String("passphrase-file", "", "файл с паролем")
	noPass := fs.Bool("no-passphrase", false, "без пароля (обычный tar.gz)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	paths := fs.Args()
	if *out == "" || len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "secrets pack --out FILE [--passphrase-file F] PATH...")
		return exitUsage
	}
	passphrase := ""
	if *noPass {
		// plain
	} else if *passFile != "" {
		p, err := readPassFile(*passFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			return exitError
		}
		passphrase = p
	} else if !yes {
		u := ui.New()
		p, err := u.ReadPasswordNew()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			return exitError
		}
		passphrase = p
	} else {
		fmt.Fprintln(os.Stderr, "укажите --passphrase-file или --no-passphrase")
		return exitUsage
	}

	if err := secretsPack(*out, passphrase, paths, log); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return exitError
	}
	return exitOK
}

func cmdSecretsUnpack(args []string, log *slog.Logger, yes bool) int {
	fs := flag.NewFlagSet("secrets unpack", flag.ContinueOnError)
	src := fs.String("src", "", "контейнер")
	out := fs.String("out", "", "каталог назначения")
	force := fs.Bool("force", false, "перезаписать")
	passFile := fs.String("passphrase-file", "", "файл с паролем")
	noPass := fs.Bool("no-passphrase", false, "контейнер без пароля")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *src == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "secrets unpack --src FILE --out DIR [--passphrase-file F]")
		return exitUsage
	}
	passphrase := ""
	if strings.HasSuffix(*src, ".mimosec") && !*noPass {
		if *passFile != "" {
			p, err := readPassFile(*passFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ошибка:", err)
				return exitPass
			}
			passphrase = p
		} else {
			u := ui.New()
			p, err := u.ReadPasswordOnce()
			if err != nil {
				fmt.Fprintln(os.Stderr, "ошибка:", err)
				return exitPass
			}
			passphrase = p
		}
	}
	if err := secretsUnpack(*src, *out, passphrase, *force); err != nil {
		code := exitError
		if errors.Is(err, restore.ErrPass) {
			code = exitPass
		}
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return code
	}
	return exitOK
}

// ---------------------------------------------------------------------------
// helpers

func mapErr(err error, log *slog.Logger) int {
	if err == nil {
		return exitOK
	}
	switch {
	case errors.Is(err, restore.ErrMimoLive):
		log.Error(err.Error())
		return exitMimoLive
	case errors.Is(err, restore.ErrVerify):
		log.Error(err.Error())
		return exitVerify
	case errors.Is(err, restore.ErrPass), errors.Is(err, secbox.ErrAuth):
		log.Error(err.Error())
		return exitPass
	case errors.Is(err, secbox.ErrPassword):
		log.Error(err.Error())
		return exitUsage
	default:
		log.Error(err.Error())
		return exitError
	}
}

func readPassFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s: слишком широкие права %o (нужны 600)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return secbox.NormalizePassphrase(b)
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// isTerminal reports whether f is a terminal (simple poll-based check).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// wizard is the zero-argument interactive flow.
func wizard(log *slog.Logger) int {
	u := ui.New()
	fmt.Fprintln(os.Stderr, "=== mimo-backup — мастер ===")

	// Detect context.
	roots := env.Discover("")
	haveData := func() bool {
		_, err := os.Stat(filepath.Join(roots.Data, "mimocode.db"))
		return err == nil
	}()
	archives := ui.DiscoverArchives()

	var options []string
	var actions []string
	if haveData {
		options = append(options, "Создать бэкап этой машины")
		actions = append(actions, "backup")
	}
	if len(archives) > 0 {
		options = append(options, "Восстановить из архива")
		actions = append(actions, "restore")
		options = append(options, "Проверить архив")
		actions = append(actions, "verify")
	}
	options = append(options, "Выйти")
	actions = append(actions, "exit")

	idx, err := u.Choose("Что делаем?", options, 0)
	if err != nil {
		log.Error(err.Error())
		return exitUsage
	}
	switch actions[idx] {
	case "exit":
		return exitOK
	case "backup":
		return wizardBackup(u, log)
	case "restore", "verify":
		return wizardRestore(u, log, actions[idx], archives)
	}
	return exitOK
}

func wizardBackup(u *ui.UI, log *slog.Logger) int {
	archives := ui.DiscoverArchives()
	_ = archives

	dest, err := u.Ask("Куда писать архив (каталог USB)", "")
	if err != nil || dest == "" {
		log.Error("каталог назначения не указан")
		return exitUsage
	}
	withSecrets, err := u.Confirm("Сохранять секреты (auth.json, ключи, токены)?", true)
	if err != nil {
		return exitUsage
	}
	passphrase := ""
	if withSecrets {
		encrypt, err := u.Confirm("Защитить секреты паролем?", true)
		if err != nil {
			return exitUsage
		}
		if encrypt {
			passphrase, err = u.ReadPasswordNew()
			if err != nil {
				return exitUsage
			}
		}
	}

	o := backup.Options{
		Dest: dest, Home: env.Discover("").Home,
		NoSecrets: !withSecrets,
		Log:       log,
	}
	pw := passphrase
	o.AskPassphrase = func() (string, error) { return pw, nil }
	o.ConfirmStopMimo = func() (bool, bool, error) {
		fmt.Fprintln(os.Stderr, "\nmimo сейчас работает и мешает созданию архива.")
		idx, err := u.Choose("Что делаем?", []string{
			"Остановить mimo и продолжить",
			"Продолжить с --hot (снимок БД, возможны недописанные файлы)",
			"Выйти и остановить mimo самому",
		}, 0)
		if err != nil {
			return false, false, err
		}
		return idx == 0, idx == 1, nil
	}
	if err := backup.Run(o); err != nil {
		return mapErr(err, log)
	}
	return exitOK
}

func wizardRestore(u *ui.UI, log *slog.Logger, action string, archives []ui.ArchiveInfo) int {
	var mains []ui.ArchiveInfo
	for _, a := range archives {
		if a.Kind == "main" {
			mains = append(mains, a)
		}
	}
	if len(mains) == 0 {
		log.Error("архивы не найдены")
		return exitUsage
	}
	opts := make([]string, len(mains))
	for i, a := range mains {
		opts[i] = fmt.Sprintf("%s  (%.1f МБ, %s)", a.Path, float64(a.Size)/(1<<20), a.ModTime.Format("2006-01-02 15:04"))
	}
	idx, err := u.Choose("Выберите архив", opts, 0)
	if err != nil {
		return exitUsage
	}
	src := mains[idx].Path

	if action == "verify" {
		return mapErr(restore.Verify(restore.Options{Src: src, Quick: true, Log: log}), log)
	}

	withSecrets, err := u.Confirm("Восстанавливать секреты?", true)
	if err != nil {
		return exitUsage
	}
	o := restore.Options{
		Src:         src,
		SkipSecrets: !withSecrets,
		Home:        env.Discover("").Home,
		Force:       true,
		Log:         log,
	}
	o.ConfirmStopMimo = func() (bool, error) {
		fmt.Fprintln(os.Stderr, "\nmimo сейчас работает и мешает распаковке.")
		ok, err := u.Confirm("Остановить mimo и продолжить?", true)
		return ok, err
	}
	o.AskPassphrase = func(encrypted bool) (string, error) {
		if !encrypted {
			return "", nil
		}
		return u.ReadPasswordOnce()
	}
	if err := restore.Restore(o); err != nil {
		return mapErr(err, log)
	}
	return exitOK
}
