#!/usr/bin/env python3
"""PreToolUse hook for Claude Code (matcher: Bash). Denies commands that cannot be undone.

Install: run install.sh from the template pack, or add to ~/.claude/settings.json:

    {"hooks": {"PreToolUse": [{"matcher": "Bash",
      "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/denylist_hook.py"}]}]}}

Input: the hook JSON on stdin ({"tool_name": "Bash", "cwd": "...", "tool_input": {"command": "..."}}).
Output: a deny decision as JSON on stdout (exit 0), or nothing (the command runs).
Unreadable input is not ignored: the hook exits with code 2 and a message on stderr.
Every denial is appended to a log (DENYLIST_HOOK_LOG, default: denylist-blocks.log next to this file, or in ~/.claude when that folder is read-only).

What it covers (mistakes, in every spelling it can see):
- Recursive deletes of broad targets: /, top-level system folders, home directories and the
  folders directly inside them, data trees such as /var/lib/*, anything with an unknown
  variable or glob, "." and "*". Relative targets are resolved against the working directory,
  including after "cd". ~, $HOME, ${HOME}, /home/<anyone>, "//", "/./" and ".." are normalized.
- find -delete / -exec rm, rsync --delete, rclone sync/purge, restic forget/prune,
  truncate, shred, recursive chmod/chown on broad targets, moving broad folders, dd to a device,
  mkfs, redirects into a block device.
- git: reset --hard, clean -f, checkout/restore ".", stash drop/clear, branch -D, reflog expire,
  gc --prune=now, every force push (--force, -f, +ref, --mirror), force-with-lease without an
  explicit non-protected branch, deleting a protected branch. "git -C", "-c" and other global
  options are skipped before the subcommand is read.
- docker/podman: system/volume prune, image prune -a, volume rm, rm -f, kill, compose down -v.
- Databases: DROP/TRUNCATE/DELETE-without-WHERE/FLUSHALL anywhere in a command that involves a
  database client (psql, mysql, mariadb, sqlite3, mongosh, redis-cli), also through
  "docker exec", pipes, here-documents and files read with "<" or "-f". dropdb, mysqladmin drop.
- gh repo delete, tmux kill-server / kill-session, crontab -r, zfs/zpool destroy, incus/lxc delete,
  kubectl delete of a namespace or "--all".
- A command name that is a variable or a substitution ($x -rf /etc, $(echo rm) ...) is denied: it
  cannot be checked. "> file" that overwrites a file in /etc, /boot, /usr, /bin, /lib* or a login or
  ssh file in your home (~/.bashrc, ~/.ssh/...) is denied.

How: the command is read like a shell would (quotes, escapes, newlines, ; && || | & ( ) { },
comments, here-documents, $(...) and backticks). Wrappers (sudo, env, timeout, nice, xargs,
bash -c, su -c, eval, ssh, docker exec ...) are unwrapped and the inner command is checked.
Text is not a command: echo "rm -rf /" is allowed.

Known limits (read these):
- This catches mistakes, not attacks. A script file that contains rm -rf, inline Python or Perl,
  base64 or "curl | sh" are not seen. systemctl stop and similar are not here on purpose: they are
  reversible and belong to the approval guard (guards.py approval). Backups and snapshots cover those.
- Symlinks are not resolved. A link that points at /etc is just a name.
- Variables other than HOME are unknown: "rm -rf $BUILD_DIR" is denied, not guessed. The same holds
  for a variable as the command name. Inside a script file, none of this is seen.
- Directly inside your home, deleting a folder is denied (rm -rf ~/projects); one level deeper is
  allowed (rm -rf ~/projects/app/dist). Do bigger cleanups yourself in a terminal.
- Redirects that overwrite a file (> file) are checked for block devices, system folders and login
  files only; any other file you can overwrite. unlink of a single file is allowed. SQL UPDATE
  without WHERE is not detected.
- find ... -delete is allowed below /tmp and /var/tmp (and on /tmp itself with a filter such as -name
  or -mtime). That trades a possible false negative (a wrongly chosen filter still deletes scratch
  files) for fewer false alarms on the most common cleanup. "cd" inside a subshell or after a pipe is treated as if it applied to the
  rest of the line, which can be wrong in either direction.
- A database command is judged by its whole text: a line that runs psql and also mentions
  DROP TABLE somewhere else is denied, even if the DROP is in a harmless echo. Rare, on purpose.
- If the parser itself fails (for example an unterminated quote), the command is denied only if
  its raw text contains a deleting word; otherwise it runs.
- Hooks do not see commands you type yourself with "!" in the prompt, and a session started with
  --bare skips hooks altogether.
"""
import codecs
import json
import os
import posixpath
import re
import sys
import time

MAX_DEPTH = 8
SAFE_ROOTS = ("/tmp/", "/var/tmp/")
PROTECTED_BRANCHES = {"main", "master", "trunk", "develop", "production", "prod", "stable", "release"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "su"}
HOME_TOPS = {"home", "Users"}
SYSTEM_TOPS = {"etc", "usr", "var", "srv", "opt", "bin", "sbin", "lib", "lib32", "lib64", "boot", "mnt",
               "media", "snap", "run", "sys", "proc", "dev", "data", "backup", "backups", "volumes"}
DEEP_SYSTEM = {("var", "lib"), ("usr", "local")}
DB_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlite", "mongo", "mongosh", "redis-cli"}
KEYWORDS = {"{", "}", "!", "then", "do", "else", "elif", "if", "while", "until", "time"}
CONTAINER_TOOLS = {"docker", "podman", "nerdctl", "kubectl", "incus", "lxc", "ssh", "nsenter"}
INNER_HEADS = {"rm", "shred", "truncate", "find", "rsync", "git", "dd", "chmod", "chown", "psql", "mysql",
               "mariadb", "sqlite3", "dropdb", "mysqladmin", "redis-cli", "bash", "sh", "zsh", "mongosh"}

# name -> (flags that take a value, number of positional words to skip)
WRAPPERS = {
    "sudo": ({"-u", "-g", "-h", "-p", "-C", "-T", "-r", "-t", "-D", "-R", "-U",
              "--user", "--group", "--host", "--prompt", "--chdir", "--role", "--type"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "env": ({"-u", "-C", "-S", "--unset", "--chdir"}, 0),
    "timeout": ({"-s", "-k", "--signal", "--kill-after"}, 1),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "-n", "-p", "-P", "-u"}, 0),
    "xargs": ({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "-l", "--max-args", "--max-procs",
               "--delimiter", "--max-lines", "--arg-file"}, 0),
    "nohup": (set(), 0), "time": ({"-f", "-o"}, 0), "command": (set(), 0), "exec": ({"-a"}, 0),
    "setsid": (set(), 0), "stdbuf": ({"-i", "-o", "-e"}, 0), "unbuffer": (set(), 0),
    "builtin": (set(), 0), "flock": ({"-w", "-E"}, 1),
    "busybox": (set(), 0), "toybox": (set(), 0),
}

SQL_DESTROY = re.compile(
    r"\b(drop\s+(table|database|schema|user|role|view|index|column)\b"
    r"|truncate\b"
    r"|delete\s+from\s+[^\s;]+\s*(;|['\"]|$)"
    r"|flushall|flushdb|dropdatabase)", re.I | re.M)
DELETE_WORDS = re.compile(
    r"\b(rm|rmdir|shred|mkfs|dd|truncate|drop|prune|delete|unlink|wipefs|force|hard)\b|-delete|--force|-rf", re.I)
BARE_WIPE = re.compile(r"^(\.{1,2}|(\./)?\*|(\./)?\.\*|\.\./\*)/?$")
# Overwriting redirects (> file) are checked against these: system files and login/ssh files.
OVERWRITE_SYSTEM_TOPS = {"etc", "boot", "usr", "bin", "sbin", "lib", "lib32", "lib64"}
HOME_DOTFILES = {".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".gitconfig"}
INTERPRETERS = re.compile(r"^(python[0-9.]*|perl|ruby|node|nodejs|php)$")
INLINE_DELETE = re.compile(
    r"rmtree|os\.(remove|unlink|rmdir|removedirs)|shutil\.move|\bunlink\b|\brm\s+-|rmSync|rmdirSync|unlinkSync"
    r"|\bsystem\s*\(.*\brm\b", re.I)
INLINE_CONFIG_WRITE = re.compile(r"""\.claude/(settings|hooks)|claude-code/managed|settings\.local\.json""")
INLINE_WRITE_WORDS = re.compile(r"""['"][wa]b?\+?['"]|write|dump|truncate|unlink|remove|replace|rename|\bsed\b|open""", re.I)
DECODE_TO_SHELL = re.compile(
    r"(base64\s+(-d|-D|--decode)|xxd\s+-r[a-z\s-]*)[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")
EMPTY_SOURCES = ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random")
FIND_TEST_WORDS = {"-name", "-iname", "-path", "-ipath", "-regex", "-type", "-mtime", "-mmin", "-atime",
                   "-amin", "-ctime", "-cmin", "-newer", "-user", "-group", "-size", "-perm", "-empty"}
BLOCK_DEVICE = re.compile(r"^/dev/(sd|hd|vd|xvd|nvme|mmcblk|disk|loop)")
SIZE_WORD = re.compile(r"^[+\-<>/%]?\d+[KMGTkmgt]?[Bb]?$")
_UNSET = object()


# ---------------------------------------------------------------- reading the command line

def match_paren(s, start):
    """s[start] is '('. Return the index of the matching ')'. Quotes are honoured."""
    depth, i, n = 0, start, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c in "'\"":
            j = i + 1
            while j < n and s[j] != c:
                j += 2 if (c == '"' and s[j] == "\\") else 1
            if j >= n:
                raise ValueError("unterminated quote in substitution")
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unterminated substitution")


def match_backtick(s, start):
    i = start + 1
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "`":
            return i
        i += 1
    raise ValueError("unterminated backtick")


def tokenize(cmd):
    """Return (segments, substitutions, heredoc_bodies). A segment is a list of words."""
    cmd = cmd.replace("\r\n", "\n").replace("\r", "\n")
    segs, subs, bodies = [], [], []
    words, cur, started = [], [], False
    pending = []
    n, i = len(cmd), 0

    def end_word():
        nonlocal cur, started
        if started:
            words.append("".join(cur))
        cur, started = [], False

    def end_seg():
        nonlocal words
        end_word()
        if words:
            segs.append(words)
        words = []

    while i < n:
        c = cmd[i]
        if c == "\\":
            if i + 1 < n and cmd[i + 1] == "\n":
                i += 2
            elif i + 1 < n:
                cur.append(cmd[i + 1]); started = True; i += 2
            else:
                i += 1
        elif c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                raise ValueError("unterminated quote")
            cur.append(cmd[i + 1:j]); started = True; i = j + 1
        elif c == '"':
            k, started = i + 1, True
            while True:
                if k >= n:
                    raise ValueError("unterminated quote")
                ch = cmd[k]
                if ch == "\\" and k + 1 < n:
                    if cmd[k + 1] in '"\\$`':
                        cur.append(cmd[k + 1])
                    elif cmd[k + 1] != "\n":
                        cur.append(ch + cmd[k + 1])
                    k += 2
                elif ch == '"':
                    break
                elif ch == "$" and cmd.startswith("$(", k):
                    j = match_paren(cmd, k + 1)
                    subs.append(cmd[k + 2:j]); cur.append(cmd[k:j + 1]); k = j + 1
                elif ch == "`":
                    j = match_backtick(cmd, k)
                    subs.append(cmd[k + 1:j]); cur.append(cmd[k:j + 1]); k = j + 1
                else:
                    cur.append(ch); k += 1
            i = k + 1
        elif c == "$" and cmd.startswith("$(", i):
            j = match_paren(cmd, i + 1)
            subs.append(cmd[i + 2:j]); cur.append(cmd[i:j + 1]); started = True; i = j + 1
        elif c == "$" and cmd.startswith("$'", i):
            j = i + 2
            while j < n and cmd[j] != "'":
                j += 2 if cmd[j] == "\\" else 1
            if j >= n:
                raise ValueError("unterminated quote")
            try:
                cur.append(codecs.decode(cmd[i + 2:j], "unicode_escape"))
            except Exception:
                cur.append(cmd[i + 2:j])
            started = True; i = j + 1
        elif c == "`":
            j = match_backtick(cmd, i)
            subs.append(cmd[i + 1:j]); cur.append(cmd[i:j + 1]); started = True; i = j + 1
        elif c == "<" and cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
            j = i + 2
            if j < n and cmd[j] == "-":
                j += 1
            while j < n and cmd[j] in " \t":
                j += 1
            delim = []
            if j < n and cmd[j] in "'\"":
                q = cmd[j]
                e = cmd.find(q, j + 1)
                if e < 0:
                    raise ValueError("unterminated quote")
                delim = cmd[j + 1:e]; j = e + 1
            else:
                s = j
                while j < n and cmd[j] not in " \t\n;&|()<>":
                    j += 1
                delim = cmd[s:j]
            pending.append("".join(delim))
            i = j
        elif c == "#" and not started and (i == 0 or cmd[i - 1] in " \t\n;&|()"):
            while i < n and cmd[i] != "\n":
                i += 1
        elif c in " \t":
            end_word(); i += 1
        elif c == "\n":
            end_seg()
            i += 1
            for delim in pending:
                body = []
                while i < n:
                    e = cmd.find("\n", i)
                    e = n if e < 0 else e
                    line = cmd[i:e]
                    i = min(e + 1, n)
                    if line.strip() == delim:
                        break
                    body.append(line)
                bodies.append("\n".join(body))
            pending = []
        elif c == "&" and ((i > 0 and cmd[i - 1] in "<>") or (i + 1 < n and cmd[i + 1] == ">")):
            cur.append(c); started = True; i += 1
        elif c in ";&|()":
            end_seg(); i += 1
        else:
            cur.append(c); started = True; i += 1
    end_seg()
    return segs, subs, bodies


REDIRECT = re.compile(r"^(\d*)(<<<|>>|>\||&>>|&>|>&|>|<)(.*)$", re.S)


def strip_redirects(argv):
    out, redirs, k = [], [], 0
    while k < len(argv):
        a = argv[k]
        m = REDIRECT.match(a)
        if m:
            op, target = m.group(2), m.group(3)
            if not target and k + 1 < len(argv):
                target = argv[k + 1]; k += 1
            redirs.append((op, target))
        else:
            out.append(a)
        k += 1
    return out, redirs


def strip_head(argv):
    while argv and (argv[0] in KEYWORDS or re.match(r"^[A-Za-z_]\w*=", argv[0])):
        argv = argv[1:]
    return argv


def unwrap(argv):
    """Strip sudo/env/timeout/xargs ... Return (argv, fed_by_xargs)."""
    via = False
    argv = strip_head(argv)
    while argv:
        name = os.path.basename(argv[0])
        if name not in WRAPPERS:
            break
        if name == "xargs":
            via = True
        valued, skip = WRAPPERS[name]
        rest, k = argv[1:], 0
        while k < len(rest):
            a = rest[k]
            if a == "--":
                k += 1
                break
            if a.startswith("-") and a != "-":
                k += 2 if a in valued else 1
            elif "=" in a and re.match(r"^[A-Za-z_]\w*=", a):
                k += 1
            elif skip > 0:
                skip -= 1; k += 1
            else:
                break
        argv = strip_head(rest[k:])
    return argv, via


def split_args(args):
    shorts, longs, pos, rest = set(), [], [], False
    for a in args:
        if rest:
            pos.append(a)
        elif a == "--":
            rest = True
        elif a.startswith("--"):
            longs.append(a)
        elif a.startswith("-") and len(a) > 1:
            shorts.update(a[1:])
        else:
            pos.append(a)
    return shorts, longs, pos


# ---------------------------------------------------------------- paths

def home_dir():
    home = os.environ.get("HOME") or os.path.expanduser("~")
    home = re.sub(r"^/+", "/", home).rstrip("/")
    return home if home not in ("", "/") else None


def expand(p):
    home = home_dir() or ""
    if home:
        p = re.sub(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])", lambda _m: home, p)
    if home and (p == "~" or p.startswith("~/")):
        p = home + p[1:]
    elif p.startswith("~"):
        m = re.match(r"^(~[\w.-]+)(/.*)?$", p)
        if m:
            e = os.path.expanduser(m.group(1))
            if not e.startswith("~"):
                p = e + (m.group(2) or "")
    return p


def make_absolute(p, cwd):
    if p.startswith("/"):
        full = p
    elif cwd:
        full = cwd + "/" + p
    else:
        return None
    full = posixpath.normpath(full)
    return re.sub(r"^/+", "/", full)


def classify(path, strict=False):
    """Reason if this absolute, glob-free path is too broad to delete, else None."""
    parts = [x for x in path.split("/") if x]
    if not parts:
        return "the root directory"
    if len(parts) == 1:
        return "a top-level directory"
    top = parts[0]
    home = home_dir()
    if home:
        hp = [x for x in home.split("/") if x]
        if path == home or home.startswith(path.rstrip("/") + "/"):
            return "your home directory or one of its parents"
        if not strict and path.startswith(home + "/") and len(parts) == len(hp) + 1:
            return "a folder directly inside your home directory"
    if top in HOME_TOPS or top == "root":
        if len(parts) == 2:
            return "a home directory"
        if len(parts) == 3 and not strict:
            return "a folder directly inside a home directory"
    if top in SYSTEM_TOPS:
        if len(parts) <= 2:
            return "a system or data directory"
        if (parts[0], parts[1]) in DEEP_SYSTEM and len(parts) <= 3:
            return "a system data directory"
    return None


def risky_path(p, cwd, strict=False):
    """Reason if deleting/changing this target recursively is too broad or unclear, else None."""
    q = expand(p)
    if not strict and BARE_WIPE.match(q):
        return "it wipes the working directory"
    unknown = "$" in q or "`" in q or q.startswith("~")
    if q.startswith("$") or q.startswith("`"):
        return "it starts with a variable or command substitution (it may be empty or absolute)"
    full = make_absolute(q, cwd)
    if full is None:
        return "unknown variable or path" if unknown else None
    if full.startswith(SAFE_ROOTS):
        return None
    if unknown:
        return "it contains a variable or command substitution"
    comps = full.split("/")
    for idx, comp in enumerate(comps):
        if any(ch in comp for ch in "*?[{"):
            prefix = "/".join(comps[:idx]) or "/"
            why = classify(prefix, strict)
            if why:
                return "the glob sits inside " + why
            return None
    return classify(full, strict)


# ---------------------------------------------------------------- checks

def overwrites_important(target, cwd):
    if not target or target.startswith("&"):
        return False
    full = make_absolute(expand(target), cwd)
    if not full:
        return False
    parts = [x for x in full.split("/") if x]
    if len(parts) >= 2 and parts[0] in OVERWRITE_SYSTEM_TOPS:
        return True
    home = home_dir()
    if home and full.startswith(home + "/"):
        rel = full[len(home) + 1:].split("/")
        if len(rel) == 1 and rel[0] in HOME_DOTFILES:
            return True
        if rel[0] == ".ssh":
            return True
    return False


def config_protected(target, cwd):
    """True for the agent's own settings and hook files and the managed-settings folder: switching these
    off is how the protection itself gets removed."""
    if not target or target.startswith("&"):
        return False
    full = make_absolute(expand(target), cwd)
    if not full:
        return False
    parts = [x for x in full.split("/") if x]
    if parts[:2] == ["etc", "claude-code"]:
        return True
    for k, comp in enumerate(parts):
        if comp == ".claude" and k + 1 < len(parts):
            nxt = parts[k + 1]
            if nxt in ("settings.json", "settings.local.json", "approvals-used.log") or (nxt == "hooks" and k + 2 < len(parts)):
                return True
    return False


def login_or_config(target, cwd):
    """Always off limits to write: login files, ssh files, the agent's own settings and hooks."""
    if config_protected(target, cwd):
        return True
    full = make_absolute(expand(target), cwd) if target else None
    home = home_dir()
    if full and home and full.startswith(home + "/"):
        rel = full[len(home) + 1:].split("/")
        return (len(rel) == 1 and rel[0] in HOME_DOTFILES) or rel[0] == ".ssh"
    return False


def write_target_reason(target, cwd, source=None, append=False):
    """Reason if writing this file (replacing its content, or changing its name) must be denied."""
    if config_protected(target, cwd):
        return "it would change the agent's own settings or hook files (%s)" % target
    if append:
        return None
    if login_or_config(target, cwd):
        return "it overwrites a login or ssh file (%s)" % target
    if overwrites_important(target, cwd):
        full = make_absolute(expand(target), cwd)
        if source in EMPTY_SOURCES or (full and os.path.lexists(full)):
            return "it overwrites a system file (%s)" % target
    return None


def read_sql_file(path, cwd):
    full = make_absolute(expand(path), cwd)
    if not full:
        return ""
    try:
        with open(full, "r", errors="replace") as fh:
            return fh.read(1_000_000)
    except OSError:
        return ""


def check_git(args, state):
    k = 0
    while k < len(args):
        a = args[k]
        if a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            k += 2
        elif a.startswith("-"):
            k += 1
        else:
            break
    if k >= len(args):
        return None
    sub = args[k]
    shorts, longs, pos = split_args(args[k + 1:])
    if sub == "push":
        lease = any(x.startswith("--force-with-lease") or x == "--force-if-includes" for x in longs)
        force = "--force" in longs or "f" in shorts
        delete = "--delete" in longs or "d" in shorts
        refspecs = pos[1:]
        if "--mirror" in longs:
            return "git push --mirror"
        if force or any(r.startswith("+") for r in refspecs):
            return "force push"
        for r in refspecs:
            dest = r.lstrip("+")
            if ":" in dest:
                dest = dest.split(":", 1)[1]
            dest = dest.replace("refs/heads/", "")
            if dest in PROTECTED_BRANCHES and (lease or delete or r.startswith(":")):
                return "force push or delete of the protected branch " + dest
        if lease and not refspecs:
            return "force-with-lease push without an explicit branch"
    elif sub == "reset" and "--hard" in longs:
        return "git reset --hard"
    elif sub == "clean" and ("f" in shorts or "--force" in longs) \
            and not ("n" in shorts or "--dry-run" in longs):
        return "git clean -f"
    elif sub == "checkout" and ("." in pos or "f" in shorts or "--force" in longs):
        return "git checkout that discards working tree changes"
    elif sub == "restore" and "." in pos and "--staged" not in longs:
        return "git restore ."
    elif sub == "switch" and ("f" in shorts or "--force" in longs or "--discard-changes" in longs):
        return "git switch --force"
    elif sub == "stash" and pos[:1] and pos[0] in ("drop", "clear"):
        return "git stash drop/clear"
    elif sub == "branch" and ("D" in shorts or (("d" in shorts or "--delete" in longs)
                                                 and ("f" in shorts or "--force" in longs))):
        return "git branch -D"
    elif sub == "reflog" and pos[:1] == ["expire"]:
        return "git reflog expire"
    elif sub == "gc" and any(x in ("--prune=now", "--prune=all") for x in longs):
        return "git gc --prune=now"
    elif sub == "filter-branch":
        return "git filter-branch"
    return None


def has_seq(seq, items):
    n = len(seq)
    return any(items[i:i + n] == seq for i in range(len(items) - n + 1))


def check_container(name, args, state, depth):
    nonflag = [a for a in args if not a.startswith("-")]
    shorts, longs, _ = split_args(args)
    force = "f" in shorts or "--force" in longs
    if name in ("docker", "podman", "nerdctl", "docker-compose"):
        if has_seq(["system", "prune"], nonflag):
            return "docker system prune"
        if has_seq(["volume", "prune"], nonflag):
            return "docker volume prune"
        if has_seq(["volume", "rm"], nonflag) or has_seq(["volume", "remove"], nonflag):
            return "docker volume rm"
        if has_seq(["image", "prune"], nonflag) and ("a" in shorts or "--all" in longs):
            return "docker image prune -a"
        if (nonflag[:1] == ["rm"] or has_seq(["container", "rm"], nonflag)) and force:
            return "docker rm -f"
        if nonflag[:1] == ["kill"] or has_seq(["container", "kill"], nonflag):
            return "docker kill"
        if name == "docker-compose" or "compose" in nonflag:
            if "down" in nonflag and ("v" in shorts or "--volumes" in longs):
                return "compose down -v"
            if "rm" in nonflag and "v" in shorts:
                return "compose rm -v"
    if name in ("incus", "lxc"):
        groups = {"storage", "project", "network", "profile", "image", "snapshot", "file", "config", "volume"}
        first = nonflag[:1]
        if first and (first[0] in ("delete", "rm")
                      or (first[0] in groups and nonflag[1:2] and nonflag[1] in ("delete", "rm", "destroy"))):
            return name + " delete"
    if name == "kubectl" and nonflag[:1] == ["delete"]:
        kinds = ("namespace", "namespaces", "ns", "all", "pv", "persistentvolume", "persistentvolumes", "pvc")
        if "--all" in longs or "A" in shorts or (nonflag[1:2] and nonflag[1].split(",")[0] in kinds):
            return "kubectl delete of a namespace or of everything"
    for k, a in enumerate(args):
        if os.path.basename(a) in INNER_HEADS:
            r = check_argv(args[k:], state, depth + 1)
            if r:
                return r
        if name == "ssh" and re.search(r"\s", a):
            r = _check(a, state["cwd"], depth + 1)
            if r:
                return r
    return None


def find_delete_is_scratch(args, cwd):
    """find ... -delete is fine under /tmp or /var/tmp. The folder itself needs a filter
    (-name, -mtime ...): 'find /tmp -delete' would also remove other programs' sockets."""
    starts = []
    for a in args:
        if a.startswith("-") or a in ("(", "!", ")"):
            break
        starts.append(a)
    if not starts:
        return False
    filtered = any(a in FIND_TEST_WORDS for a in args)
    for p in starts:
        if ".." in p.split("/"):
            return False
        full = make_absolute(expand(p), cwd)
        if not full or "$" in full or "`" in full:
            return False
        if full.rstrip("/") in ("/tmp", "/var/tmp"):
            if not filtered:
                return False
        elif not full.startswith(SAFE_ROOTS):
            return False
    return True


def check_writers(name, args, shorts, longs, pos, state, cwd, via_xargs):
    """Commands that replace, remove or rename a file without a redirect: cp, mv, ln, install, tee,
    sed -i, rm, unlink, chmod and inline interpreter code. Returns a deny reason or None."""
    if name in ("rm", "unlink", "shred") and via_xargs and state.get("find_wide"):
        return "%s fed by a find over a broad tree (the list is not visible here)" % name
    if name in ("rm", "unlink"):
        for p in pos:
            why = write_target_reason(p, cwd)
            if why:
                return "%s: %s" % (name, why)
    elif name == "tee":
        for p in pos:
            why = write_target_reason(p, cwd, append="a" in shorts or "--append" in longs)
            if why:
                return "tee: " + why
    elif name in ("cp", "install", "ln", "mv") and pos:
        if "t" in shorts and len(pos) >= 2 and name != "ln":
            dest_candidates = [pos[0]]
        else:
            dest_candidates = [pos[-1]]
        source = next((x for x in pos[:-1] if x in EMPTY_SOURCES), None)
        for d in dest_candidates:
            why = write_target_reason(d, cwd, source=source)
            if why:
                return "%s: %s" % (name, why)
        if name == "mv":
            for p in pos[:-1]:
                if config_protected(p, cwd):
                    return "mv: it would move the agent's own settings or hook files (%s)" % p
    elif name == "sed" and ("i" in shorts or any(x.startswith("--in-place") for x in longs)):
        for p in pos:
            why = write_target_reason(p, cwd)
            if why:
                return "sed -i: " + why
    elif name in ("chmod", "chown", "chgrp"):
        for p in pos:
            if config_protected(p, cwd):
                return "%s: it would change the agent's own settings or hook files (%s)" % (name, p)
    elif INTERPRETERS.match(name):
        state["interp"] = True
        text = " ".join(args)
        return inline_reason(text)
    return None


def inline_reason(text):
    if INLINE_DELETE.search(text):
        return "inline interpreter code that deletes files cannot be checked"
    if INLINE_CONFIG_WRITE.search(text) and INLINE_WRITE_WORDS.search(text):
        return "inline interpreter code that writes the agent's own settings or hook files"
    return None


def check_simple(argv, state, depth, via_xargs=False):
    name = os.path.basename(argv[0])
    args = argv[1:]
    shorts, longs, pos = split_args(args)
    cwd = state["cwd"]

    why = check_writers(name, args, shorts, longs, pos, state, cwd, via_xargs)
    if why:
        return why
    if name == "rm":
        if "r" in shorts or "R" in shorts or "--recursive" in longs:
            if via_xargs or not pos:
                return "recursive delete with targets I cannot see"
            for p in pos:
                why = risky_path(p, cwd)
                if why:
                    return "recursive delete of %s (%s)" % (p, why)
    elif name == "shred":
        if not all(risky_path(p, cwd) is None and make_absolute(expand(p), cwd) or "" for p in pos) \
                or not all((make_absolute(expand(p), cwd) or "").startswith(SAFE_ROOTS) for p in pos):
            return "shred"
    elif name == "truncate":
        targets = [p for p in pos if not SIZE_WORD.match(p)]
        if not targets or not all((make_absolute(expand(p), cwd) or "").startswith(SAFE_ROOTS) for p in targets):
            return "truncate outside /tmp"
    elif name == "find":
        roots = []
        for a in args:
            if a.startswith("-") or a in ("(", ")", "!"):
                break
            roots.append(a)
        if any(risky_path(r, cwd, strict=True) for r in roots or ["."]):
            state["find_wide"] = True
        if "-delete" in args:
            if not find_delete_is_scratch(args, cwd):
                return "find -delete"
        for k, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                sub = []
                for b in args[k + 1:]:
                    if b in (";", "+"):
                        break
                    sub.append(b)
                if sub:
                    r = check_argv(sub, state, depth + 1, via_xargs=True)
                    if r:
                        return "find -exec: " + r
    elif name == "rsync":
        dry = "n" in shorts or "--dry-run" in longs
        if not dry and any(x.startswith("--delete") or x in ("--del", "--remove-source-files",
                                                           "--remove-sent-files") for x in longs):
            return "rsync with --delete or --remove-source-files"
    elif name == "rclone":
        if pos[:1] and pos[0] in ("sync", "purge", "delete", "deletefile", "cleanup") \
                and "--dry-run" not in longs and "n" not in shorts:
            return "rclone " + pos[0]
    elif name == "restic":
        if any(p in ("forget", "prune") for p in pos[:1]) and "--dry-run" not in longs:
            return "restic forget/prune"
    elif name == "borg":
        if pos[:1] and pos[0] in ("delete", "prune"):
            return "borg " + pos[0]
    elif name in ("chmod", "chown", "chgrp"):
        if "R" in shorts or "--recursive" in longs:
            for p in pos[1:]:
                why = risky_path(p, cwd, strict=True)
                if why:
                    return "recursive %s of %s (%s)" % (name, p, why)
    elif name == "mv":
        for p in pos[:-1]:
            why = risky_path(p, cwd, strict=True)
            if why:
                return "moving %s (%s)" % (p, why)
    elif name == "dd":
        if any(a.startswith("of=/dev/") for a in args):
            return "dd to a device"
        for a in args:
            if a.startswith("of=") and write_target_reason(a[3:], cwd, source="/dev/null"):
                return "dd: " + write_target_reason(a[3:], cwd, source="/dev/null")
    elif name in ("wipefs", "blkdiscard") or name == "mkfs" or name.startswith("mkfs."):
        return name
    elif name == "tmux":
        if args[:1] and args[0] in ("kill-server", "kill-session"):
            return "tmux kill"
    elif name == "crontab":
        if "r" in shorts:
            return "crontab -r (removes every scheduled job)"
    elif name in ("zfs", "zpool"):
        if pos[:1] == ["destroy"]:
            return name + " destroy"
    elif name == "git":
        return check_git(args, state)
    elif name == "gh":
        if has_seq(["repo", "delete"], pos):
            return "gh repo delete"
        if "DELETE" in args and ("-X" in args or "--method" in args):
            return "gh api DELETE"
    elif name in ("dropdb", "dropuser"):
        return name
    elif name == "mysqladmin":
        if any(p in ("drop", "shutdown") for p in pos):
            return "mysqladmin " + " ".join(p for p in pos if p in ("drop", "shutdown"))
    if name in DB_CLIENTS or name in ("dropdb", "dropuser", "mysqladmin"):
        state["db"] = True
        for k, a in enumerate(args):
            if a in ("-f", "--file") and k + 1 < len(args):
                state["files"].append(args[k + 1])
            elif a.startswith("--file="):
                state["files"].append(a[7:])
    if name in CONTAINER_TOOLS or name == "docker-compose":
        return check_container(name, args, state, depth)
    return None


def do_cd(args, state):
    _, _, pos = split_args(args)
    if not pos:
        home = home_dir()
        state["cwd"] = home
        return
    target = expand(pos[0])
    if pos[0] == "-" or "$" in target or "`" in target or target.startswith("~") \
            or any(ch in target for ch in "*?[{"):
        state["cwd"] = None
        return
    state["cwd"] = make_absolute(target, state["cwd"])


def check_argv(argv, state, depth, via_xargs=False):
    argv, via = unwrap(argv)
    via_xargs = via_xargs or via
    if not argv:
        return None
    head = expand(argv[0])
    if "$" in head or "`" in head:
        return "the command name comes from a variable or substitution, so it cannot be checked"
    name = os.path.basename(argv[0])
    args = argv[1:]
    if name in ("cd", "pushd"):
        do_cd(args, state)
        return None
    if name == "eval":
        return _check(" ".join(args), state["cwd"], depth + 1)
    if name in SHELLS:
        for k, a in enumerate(args):
            if a == "--":
                break
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and k + 1 < len(args):
                return _check(args[k + 1], state["cwd"], depth + 1)
            if a == "--command" and k + 1 < len(args):
                return _check(args[k + 1], state["cwd"], depth + 1)
        state["shell_stdin"] = True
        return None
    return check_simple(argv, state, depth, via_xargs)


def simple_commands(command, depth=0, inherited=()):
    """Yield (argv, assigns) for every simple command in a command line, looking through
    sudo/env/nohup, eval, 'bash -c' and $(...). assigns = OWNER_APPROVAL=... words that
    stood in front of the command. Used by guards.py."""
    if depth > MAX_DEPTH:
        raise ValueError("command nested too deeply")
    segs, subs, _ = tokenize(command)
    for sub in subs:
        yield from simple_commands(sub, depth + 1)
    for raw in segs:
        argv, _ = strip_redirects(raw)
        final, _ = unwrap(argv)
        if not final:
            continue
        assigns = list(inherited) + [t for t in argv[:len(argv) - len(final)] if t.startswith("OWNER_APPROVAL=")]
        name = os.path.basename(final[0])
        args = final[1:]
        if name == "eval":
            yield from simple_commands(" ".join(args), depth + 1, assigns)
            continue
        if name in SHELLS:
            inner = None
            for k, a in enumerate(args):
                if a == "--":
                    break
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and k + 1 < len(args):
                    inner = args[k + 1]
                    break
                if a == "--command" and k + 1 < len(args):
                    inner = args[k + 1]
                    break
            if inner is not None:
                yield from simple_commands(inner, depth + 1, assigns)
                continue
        yield final, assigns


def sql_reason(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    m = SQL_DESTROY.search(text)
    return "destructive SQL (%s)" % re.sub(r"\s+", " ", m.group(0)).strip()[:40] if m else None


def _check(command, cwd, depth):
    if depth > MAX_DEPTH:
        return "command nested too deeply to check"
    segs, subs, bodies = tokenize(command)
    for s in subs:
        r = _check(s, cwd, depth + 1)
        if r:
            return r
    if DECODE_TO_SHELL.search(command):
        return "decoded text piped into a shell cannot be checked"
    state = {"cwd": cwd, "db": False, "files": [], "shell_stdin": False, "interp": False, "find_wide": False}
    for raw in segs:
        argv, redirs = strip_redirects(raw)
        for op, target in redirs:
            if op in (">", ">>", ">|", "&>", "&>>", ">&") and BLOCK_DEVICE.match(target):
                return "redirect into a block device"
            if op in (">", ">|", "&>") and (overwrites_important(target, state["cwd"])
                                            or login_or_config(target, state["cwd"])):
                return "redirect that overwrites a system or login file (%s)" % target
            if op in (">>", "&>>") and config_protected(target, state["cwd"]):
                return "redirect that appends to the agent's own settings or hook files (%s)" % target
            if op == "<" and target:
                state["files"].append(target)
        if argv:
            r = check_argv(argv, state, depth)
            if r:
                return r
    if state["interp"]:
        for body in bodies:
            r = inline_reason(body)
            if r:
                return r
    if state["shell_stdin"]:
        for body in bodies:
            r = _check(body, state["cwd"], depth + 1)
            if r:
                return r
    if state["db"]:
        r = sql_reason(command)
        if r:
            return r
        for f in state["files"]:
            r = sql_reason(read_sql_file(f, state["cwd"]))
            if r:
                return r + " in " + f
    return None


def decide(command, cwd=_UNSET):
    """Return a deny reason or None. cwd=None means the working directory is unknown."""
    if cwd is _UNSET:
        cwd = os.getcwd()
    try:
        return _check(command, cwd, 0)
    except Exception as exc:  # parser trouble: fail closed only for deleting words
        if DELETE_WORDS.search(command):
            return "could not parse a command containing a deleting word (%s)" % type(exc).__name__
    return None


def default_log(name):
    """Next to this file; in ~/.claude when that folder is not writable (root-owned managed install)."""
    here = os.path.dirname(os.path.abspath(__file__))
    if os.access(here, os.W_OK):
        return os.path.join(here, name)
    return os.path.join(os.path.expanduser("~/.claude"), name)


def log_block(reason, command):
    path = os.environ.get("DENYLIST_HOOK_LOG") or default_log("denylist-blocks.log")
    try:
        with open(path, "a") as fh:
            fh.write("%s\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), reason,
                                       command.replace("\n", "\\n")[:300]))
    except OSError as exc:
        print("denylist_hook: could not write block log: %s" % exc, file=sys.stderr)


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except Exception as exc:
        print("denylist_hook: unreadable hook input (%s); blocking to be safe. "
              "Check the Claude Code version and this hook." % exc, file=sys.stderr)
        return 2
    if data.get("tool_name") != "Bash":
        return 0
    command = (data.get("tool_input") or {}).get("command", "")
    cwd = data.get("cwd") or os.getcwd()
    reason = decide(command, cwd=cwd)
    if reason:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Blocked by denylist: " + reason
            + ". This cannot be undone. Ask the owner, or use a reversible alternative"
            " (a copy under /tmp, a dry run, a narrower path).",
        }}))
        sys.stdout.flush()
        log_block(reason, command)
    return 0


if __name__ == "__main__":
    sys.exit(main())
