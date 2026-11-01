# denylist-hook

This repository is written and maintained by an AI (Claude) on behalf of a sole proprietor (Desk of 0ne). Not affiliated with or endorsed by Anthropic.

A small, tested PreToolUse hook for Claude Code that blocks commands you cannot undo, even when Claude runs without permission prompts.

It denies, among others:

- recursive deletes on broad or unclear targets (`rm -rf /`, `rm -rf ~`, `rm -rf $HOME/..`, `rm -rf $UNSET`, `rm -rf *`), in any path spelling, also behind `cd`, `sudo`, `xargs`, `bash -c`, `$(...)`, backticks, `ssh` and `docker exec`; `find -delete` outside `/tmp` and `/var/tmp` (below those it is allowed; `/tmp` itself needs a filter such as `-name`); `rsync --delete`; `rclone sync`; `restic forget`
- `git push --force` (also `-f`, `+main`, `--mirror`, `git -C path push ...`), `git reset --hard`, `git clean -f`, `git checkout .`, `git stash drop`, `git branch -D`
- `docker system prune`, `docker volume prune`, `docker compose down -v`, `docker rm -f`
- `dd` to a device, `mkfs`, redirects into a block device
- `tmux kill-server` and `kill-session`, `crontab -r`, `zfs`/`zpool destroy`, `incus`/`lxc delete`, `kubectl delete` of a namespace or `--all`
- a command name taken from a variable (`$x -rf /etc`), and `>` redirects that overwrite files in `/etc`, `/usr`, `/boot`, `/bin`, `/lib*`, `~/.bashrc`, `~/.ssh/*`
- `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, `DELETE FROM x` without WHERE, `FLUSHALL` through `psql`, `mysql`, `mariadb`, `sqlite3`, `redis-cli`, also via `docker exec`, pipes, here-documents and files

It allows harmless lookalikes: `rm file.txt`, `rm -rf /tmp/scratch`, `rm -rf ./build`, `git push --force-with-lease origin feature-x`, `echo 'rm -rf /' > notes.txt`, `grep -r 'DROP TABLE' docs/`.

## How it works

The hook reads the tool call as JSON on stdin, reads the command like a shell would (quotes, escapes, newlines, separators, here-documents, `$(...)`), unwraps `sudo`, `env`, `timeout`, `bash -c` and similar wrappers, and checks each simple command on its own. Text inside quotes is not a command. Relative paths are resolved against the working directory the hook receives. If the parser fails and the raw text contains a deleting verb, the hook denies (fail closed). Unreadable hook input exits with code 2 and a message. Every denial is appended to `denylist-blocks.log` next to the hook (`DENYLIST_HOOK_LOG` changes it).

## Install

1. Copy `denylist_hook.py` to `~/.claude/hooks/`.
2. Add to `~/.claude/settings.json`:

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash",
  "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/denylist_hook.py"}]}]}}
```

3. Run the tests: `sudo apt install python3-pytest` (or `python3 -m venv .venv && .venv/bin/pip install pytest`), then `pytest -q`.
4. In a scratch session, ask Claude to run `git reset --hard` in a throwaway repository. The hook should deny it.

## Extend it

Add the new case to `DENIED_REVIEW` or `ALLOWED` in `test_denylist_hook.py` first, watch it fail, then add the rule to `check_simple` (or `check_git`, `check_container`) in the hook.

## Limits

This hook catches mistakes, not attacks. Script files, inline Python, base64 and symlinks bypass a check on the command text. Deleting a folder directly inside your home is denied on purpose (false positives exist); variables other than `HOME` are treated as unknown and denied. Commands you type yourself with `!` do not pass hooks. The full list is in the hook's docstring ("Known limits"). Keep backups and snapshots. A rule in CLAUDE.md is a request; a hook is a lock, and a lock needs a restore plan behind it.

## The full manual

This hook is the sample from one chapter of a manual for non-developers who run a live server with Claude Code as their whole staff: roles, memory, verification, alerts, cost control, more hooks and recovery.

The manual: https://deskof0ne.gumroad.com/l/rponee. It costs 123 EUR. This hook works without it.

Independent project, not affiliated with or endorsed by Anthropic. Claude and Claude Code are trademarks of Anthropic.

This hook will have gaps. If it lets a destructive command through, or blocks a harmless one, open an issue with the exact command. Every report becomes a test case first, then a fix.

## License

MIT, see `LICENSE`.
