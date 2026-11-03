import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from denylist_hook import decide  # noqa: E402

HOME = "/home/dana"
CWD = "/home/dana/projects/app"


@pytest.fixture(autouse=True)
def fixed_home(monkeypatch):
    monkeypatch.setenv("HOME", HOME)


# Original cases from the first release.
DENIED_BASIC = [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf ~/*",
    "rm -r /home",
    "rm -rf $UNSET_DIR",
    "sudo rm -rf /etc",
    "bash -c 'rm -rf /'",
    "echo hi && rm -rf /var",
    "find . -name '*.log' -delete",
    "git push --force origin main",
    "git push -f origin master",
    "git reset --hard HEAD~3",
    "git clean -fd",
    "git branch -D old",
    "docker system prune -a",
    "docker volume prune",
    "docker compose down -v",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sdb1",
    "tmux kill-server",
    "psql -c 'DROP TABLE users;'",
    "mysql -e 'truncate orders'",
    "timeout 5 env FOO=1 rm -rf /usr",
]

# Everything that slipped through in review 1 (a hostile buyer's probes), plus
# further classes of honest mistakes. Each of these must be denied.
DENIED_REVIEW = [
    # home and system trees, path spellings
    "rm -rf ~/",
    "rm -rf /home/dana",
    "rm -rf /home/dana/",
    "rm -rf ~/projects",
    "rm -rf ~/.claude",
    "rm -rf $HOME",
    "rm -rf ${HOME}",
    'rm -rf "$HOME"/',
    "rm -rf $HOME/projects",
    "rm -rf /home/someoneelse",
    "rm -rf /Users/anyone",
    "rm -rf /root",
    "rm -rf /var/lib/docker",
    "rm -rf /var/lib/mysql",
    "rm -rf /var/www",
    "rm -rf /srv/app",
    "rm -rf /opt/app",
    "rm -rf /tmp/../etc",
    "rm -rf //",
    "rm -rf /./",
    "rm -rf /*",
    "rm -rf /home/dana/*",
    "rm -rf /{etc,var}",
    "rm -rf -- /etc",
    "rm -Rf /etc",
    "rm --recursive --force /etc",
    "rm -rf --no-preserve-root /",
    "rm -rf .",
    "rm -rf ..",
    "rm -rf *",
    "rm -rf ./*",
    "rm -rf .*",
    # relative targets after a cd
    "cd / && rm -rf etc",
    "cd /etc && rm -rf .",
    "cd ~ && rm -rf projects",
    "cd /var/lib && rm -rf docker",
    # multi-line, substitution, eval, wrappers
    "echo hi\nrm -rf /etc",
    "echo hi\r\nrm -rf /etc",
    "echo hi \\\n && rm -rf /etc",
    "echo $(rm -rf /etc)",
    "echo `rm -rf /etc`",
    'echo "$(rm -rf /etc)"',
    'echo "`rm -rf /etc`"',
    "rm -rf $(echo /etc)",
    "rm -rf `echo /etc`",
    "eval 'rm -rf /etc'",
    "bash -lc 'rm -rf /etc'",
    "sh -ec 'rm -rf /etc'",
    "sudo -u root rm -rf /etc",
    "sudo -- rm -rf /etc",
    "sudo -E -u root -g root rm -rf /etc",
    "env -i rm -rf /etc",
    "env -u FOO rm -rf /etc",
    "FOO=1 rm -rf /etc",
    "nice -n 10 rm -rf /etc",
    "xargs rm -rf",
    "echo /etc | xargs rm -rf",
    "xargs -I {} rm -rf {}",
    "(rm -rf /etc)",
    "{ rm -rf /etc; }",
    "for d in /etc /var; do rm -rf $d; done",
    "if true; then rm -rf /etc; fi",
    "ssh server 'rm -rf /etc'",
    "docker exec web rm -rf /var/lib/mysql",
    "kubectl exec pod -- rm -rf /data",
    "su root -c 'rm -rf /etc'",
    "cat <<EOF | bash\nrm -rf /etc\nEOF",
    "bash <<EOF\nrm -rf /etc\nEOF",
    "rm $'-rf' /etc",
    # find, rsync, truncate and friends
    "find . -exec rm -rf {} +",
    "find /var -name x -exec rm -rf {} \\;",
    "find . -delete",
    "rsync -a --delete src/ dst/",
    "rsync -a --delete-after src/ dst/",
    "rsync --remove-source-files src/ dst/",
    "truncate -s 0 db.sqlite",
    "shred -u secrets.txt",
    "chmod -R 000 /",
    "chmod -R 777 ~",
    "chown -R nobody /etc",
    "mv ~ /tmp/old-home",
    "mv /etc /etc.old",
    "echo x > /dev/sda",
    "rclone purge remote:bucket",
    "rclone sync /data remote:bucket",
    "restic forget --prune --keep-last 1",
    # git
    "git -C /srv/app reset --hard",
    "git -C repo push --force origin main",
    "git -c core.pager=cat reset --hard",
    "git --no-pager reset --hard",
    "git push --force origin HEAD:main",
    "git push origin +main",
    "git push origin +HEAD:main",
    "git push origin HEAD:refs/heads/main --force",
    "git push --force origin feature-x",
    "git push -f",
    "git push --force-with-lease",
    "git push --force-with-lease origin main",
    "git push origin --delete main",
    "git push origin :main",
    "git push --mirror origin",
    "git push origin +feature-x",
    "git clean --force -d",
    "git clean -xdf",
    "git checkout -- .",
    "git checkout .",
    "git restore .",
    "git stash drop",
    "git stash clear",
    "git reset --hard",
    "git -C /x branch -D old",
    "git branch --delete --force old",
    "git reflog expire --expire=now --all",
    "git gc --prune=now",
    # docker
    "docker-compose down -v",
    "docker compose -f x.yml down --volumes",
    "docker volume rm data",
    "docker rm -f web",
    "docker container rm -f web",
    "docker image prune -a",
    "docker system prune",
    "docker-compose rm -sv",
    "podman system prune -a",
    # databases
    "docker exec db psql -c 'DROP TABLE users'",
    "docker exec -it db mysql -e 'drop database shop'",
    "docker compose exec db psql -U app -c 'TRUNCATE users'",
    "echo 'DROP TABLE x' | psql",
    "echo 'DROP TABLE x;' | docker exec -i db psql -U app",
    "psql <<EOF\nDROP TABLE x;\nEOF",
    "psql <<< 'drop table x'",
    "psql -c 'DROP/**/TABLE x'",
    "psql -c 'DROP\nTABLE x'",
    "psql -c 'delete from users'",
    "psql -c 'DELETE FROM users;'",
    "mysql -e 'DROP USER app'",
    "sqlite3 app.db 'DROP TABLE t'",
    "dropdb shop",
    "mysqladmin drop shop",
    "redis-cli FLUSHALL",
    "echo 'DROP TABLE x' > a.sql && psql -f a.sql",
    "mongosh --eval 'db.dropDatabase()'",
    # misc
    "tmux kill-session -t main",
    "gh repo delete me/x --yes",
]

ALLOWED = [
    "ls -la",
    "rm file.txt",
    "rm -f /etc/hosts.bak",
    "rm -rf /tmp/scratch-123",
    "rm -rf /tmp/a /tmp/b",
    "rm -rf /var/tmp/x",
    "rm -rf ./build",
    "rm -rf build",
    "rm -rf build/*",
    "rm -rf node_modules",
    "rm -rf ~/projects/app/dist",
    "rm -rf $HOME/projects/app/dist",
    "rm -rf /home/dana/projects/app/tmp",
    "rm -rf /srv/app/cache/old",
    "cd /tmp && rm -rf scratch",
    "cd build && rm -rf cache",
    "echo 'rm -rf /' > notes.txt",
    'echo "rm -rf /etc"',
    "echo hi # rm -rf /etc",
    "cat <<EOF\nrm -rf /etc\nEOF",
    "grep -r 'rm -rf /' docs/",
    "git push",
    "git push origin feature-x",
    "git push -u origin feature-x",
    "git push --force-with-lease origin feature-x",
    "git -C /srv/app status",
    "git -C /srv/app push origin feature-x",
    "git reset --soft HEAD~1",
    "git reset HEAD file.txt",
    "git clean -n",
    "git clean -nd",
    "git branch -d merged-branch",
    "git checkout feature-x",
    "git checkout -b new",
    "git restore --staged file.txt",
    "git stash",
    "git stash pop",
    "docker compose down",
    "docker-compose down",
    "docker ps",
    "docker rm old-container",
    "docker exec web ls /var/lib",
    "docker compose exec db psql -U app -c 'SELECT 1'",
    "psql -c 'SELECT 1'",
    "psql -c 'delete from users where id = 3'",
    "mysql -e 'show tables'",
    "grep -r 'DROP TABLE' docs/",
    "rsync -a src/ dst/",
    "rsync -a --dry-run --delete src/ dst/",
    "tmux ls",
    "truncate -s 0 /tmp/x.log",
    "find . -name '*.log'",
    "find . -name '*.pyc' -exec ls {} +",
    "chmod -R u+rw build",
    "mv a.txt b.txt",
    "echo hi > out.txt 2>&1",
    "ls /nonexistent 2>&1 | head",
    "docker run --rm -v data:/d alpine ls /d",
    "ssh server 'ls /etc'",
    "cd ~ && ls",
    "echo $(date)",
    "cat file | wc -l; ls",
]


@pytest.mark.parametrize("cmd", DENIED_BASIC)
def test_denied_basic(cmd):
    assert decide(cmd, cwd=CWD) is not None, cmd


@pytest.mark.parametrize("cmd", DENIED_REVIEW)
def test_denied_review(cmd):
    assert decide(cmd, cwd=CWD) is not None, cmd


@pytest.mark.parametrize("cmd", ALLOWED)
def test_allowed(cmd):
    assert decide(cmd, cwd=CWD) is None, cmd


def test_relative_target_resolves_against_cwd():
    assert decide("rm -rf projects", cwd=HOME) is not None
    assert decide("rm -rf dist", cwd=CWD) is None


def test_unknown_cwd_still_blocks_dot_forms():
    assert decide("rm -rf .", cwd=None) is not None


def run_hook(payload):
    return subprocess.run([sys.executable, os.path.join(HERE, "denylist_hook.py")],
                          input=json.dumps(payload), capture_output=True, text=True)


def test_cli_deny_output():
    r = run_hook({"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}})
    out = json.loads(r.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "owner" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_cli_allow_is_silent():
    r = run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert r.stdout == "" and r.returncode == 0


def test_cli_ignores_other_tools():
    r = run_hook({"tool_name": "Read", "tool_input": {"command": "rm -rf /"}})
    assert r.stdout == ""


def test_cli_uses_cwd_from_payload():
    r = run_hook({"tool_name": "Bash", "cwd": "/",
                  "tool_input": {"command": "rm -rf etc"}})
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cli_unreadable_input_fails_loud():
    r = subprocess.run([sys.executable, os.path.join(HERE, "denylist_hook.py")],
                       input="not json", capture_output=True, text=True)
    assert r.returncode == 2 and "denylist_hook" in r.stderr


def test_cli_logs_block(tmp_path):
    log = tmp_path / "blocks.log"
    env = dict(os.environ, DENYLIST_HOOK_LOG=str(log))
    r = subprocess.run([sys.executable, os.path.join(HERE, "denylist_hook.py")],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}}),
                       capture_output=True, text=True, env=env)
    assert json.loads(r.stdout)
    assert "git reset --hard" in log.read_text()


def test_cli_logs_to_plugin_data_dir(tmp_path):
    env = dict(os.environ, CLAUDE_PLUGIN_DATA=str(tmp_path))
    env.pop("DENYLIST_HOOK_LOG", None)
    r = subprocess.run([sys.executable, os.path.join(HERE, "denylist_hook.py")],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}}),
                       capture_output=True, text=True, env=env)
    assert json.loads(r.stdout)
    assert "git reset --hard" in (tmp_path / "denylist-blocks.log").read_text()


def test_plugin_hooks_json_runs_this_hook():
    with open(os.path.join(HERE, "hooks", "hooks.json")) as fh:
        hooks = json.load(fh)["hooks"]["PreToolUse"]
    assert hooks[0]["matcher"] == "Bash"
    command = hooks[0]["hooks"][0]["command"]
    assert "${CLAUDE_PLUGIN_ROOT}/denylist_hook.py" in command


def test_unparseable_with_deleting_verb_is_denied():
    assert decide("rm -rf '/ unterminated", cwd=CWD) is not None


def test_unparseable_harmless_runs():
    assert decide("echo 'unterminated", cwd=CWD) is None


def test_sql_file_redirect_is_read(tmp_path):
    f = tmp_path / "drop.sql"
    f.write_text("DROP TABLE users;")
    assert decide("psql < %s" % f, cwd=CWD) is not None
    assert decide("psql -f %s" % f, cwd=CWD) is not None
    g = tmp_path / "ok.sql"
    g.write_text("SELECT 1;")
    assert decide("psql < %s" % g, cwd=CWD) is None


def test_deeply_nested_substitution_is_denied():
    cmd = "echo " + "$(echo " * 12 + "x" + ")" * 12
    assert decide(cmd, cwd=CWD) is not None


# Review 2 (second hostile buyer): classes that got through.
DENIED_REVIEW_2 = [
    "busybox rm -rf /etc",
    "sudo busybox rm -rf /etc",
    "crontab -r",
    "crontab -ri",
    "sudo crontab -r -u dana",
    "zfs destroy tank/data",
    "zfs destroy -r tank",
    "zpool destroy tank",
    "incus delete web",
    "incus delete --force web",
    "incus storage delete default",
    "incus snapshot delete web snap0",
    "lxc delete web",
    "sudo incus delete web -f",
    "kubectl delete namespace prod",
    "kubectl delete ns prod",
    "kubectl delete pods --all",
    "kubectl delete all --all -n prod",
    "x=rm; $x -rf /etc",
    "$(echo rm) -rf /etc",
    "${CMD} -rf /etc",
    "sudo $TOOL -rf /etc",
    "`echo rm` -rf /etc",
    "> /etc/passwd",
    "echo x > /etc/hosts",
    "cat /dev/null > ~/.bashrc",
    "echo > /home/dana/.ssh/authorized_keys",
    "find /tmp -delete",
    "find / -name '*.tmp' -delete",
    "find /var -delete",
]

ALLOWED_REVIEW_2 = [
    "find /tmp -name '*.tmp' -delete",
    "find /tmp/build -delete",
    "find /var/tmp -type f -mtime +7 -delete",
    "crontab -l",
    "crontab -e",
    "zfs list",
    "zfs snapshot tank/data@now",
    "incus list",
    "incus exec web -- ls delete",
    "incus snapshot create web snap0",
    "kubectl get pods",
    "kubectl delete pod web-1",
    "busybox ls -la",
    "$HOME/bin/tool --help",
    "${HOME}/bin/tool",
    "echo hi > out.txt",
    "echo hi >> /etc/hosts.bak",
    "echo hi > /tmp/x",
    "echo hi > /home/dana/projects/app/notes.txt",
    "echo hi > /dev/null",
]


@pytest.mark.parametrize("cmd", DENIED_REVIEW_2)
def test_denied_review_2(cmd):
    assert decide(cmd, cwd=CWD) is not None, cmd


@pytest.mark.parametrize("cmd", ALLOWED_REVIEW_2)
def test_allowed_review_2(cmd):
    assert decide(cmd, cwd=CWD) is None, cmd


# Review 3: overwrites without ">", broad deletes through xargs, inline interpreters, and the agent
# switching off its own protection (settings and hook files). An unset variable at the start of a path.
DENIED_REVIEW_3 = [
    "cp /dev/null /etc/passwd",
    "tee /etc/hosts < /dev/null",
    "echo x | tee /etc/hosts",
    "ln -sf /dev/null /etc/fstab",
    "install -m 600 /dev/null ~/.ssh/authorized_keys",
    "install -m 600 /dev/null /home/dana/.ssh/authorized_keys",
    "unlink /etc/passwd",
    "find /srv -type f -print0 | xargs -0 rm -f",
    "find /var/lib -name '*.db' | xargs rm",
    "python3 -c \"import shutil; shutil.rmtree('/etc')\"",
    "perl -e 'system(\"rm -rf /etc\")'",
    "python3 -c 'import os; os.remove(\"/etc/passwd\")'",
    "echo cm0gLXJmIC9ldGM= | base64 -d | sh",
    "echo cm0gLXJmIC9ldGM= | base64 --decode | bash",
    "rm -rf $ZIEL_UNGESETZT",
    "rm -rf \"$ZIEL_UNGESETZT\"",
    "rm -rf ${ZIEL_UNGESETZT}/",
    # self-disable: settings and hooks of the agent
    "sed -i '/guards.py approval/d' ~/.claude/settings.json",
    "sed -i 's/deny/allow/' /home/dana/.claude/settings.json",
    "echo '{}' > ~/.claude/settings.json",
    "echo '{}' >> ~/.claude/settings.json",
    "echo '{}' > ~/.claude/settings.local.json",
    "echo '{}' > .claude/settings.json",
    "echo '{}' > /home/dana/projects/app/.claude/settings.local.json",
    "cp /dev/null ~/.claude/hooks/denylist_hook.py",
    "rm ~/.claude/hooks/denylist_hook.py",
    "rm -f /home/dana/.claude/hooks/guards.py",
    "mv ~/.claude/settings.json /tmp/x",
    "tee ~/.claude/settings.json < /tmp/x",
    "cp /tmp/evil.py ~/.claude/hooks/denylist_hook.py",
    "python3 -c \"import json; open('/home/dana/.claude/settings.json','w').write('{}')\"",
    "echo '{}' > /etc/claude-code/managed-settings.json",
    "rm /etc/claude-code/managed-settings.json",
    "sudo sed -i 's/true/false/' /etc/claude-code/managed-settings.json",
    "chmod 777 ~/.claude/hooks/denylist_hook.py",
]

ALLOWED_REVIEW_3 = [
    "cp a.txt b.txt",
    "cp /dev/null /tmp/x",
    "tee out.log < in.txt",
    "echo x | tee /tmp/out.log",
    "ln -sf /home/dana/projects/app/current /home/dana/projects/app/live",
    "install -m 644 app.conf /home/dana/projects/app/app.conf",
    "unlink /tmp/x.lock",
    "find /srv -type f -print0 | xargs -0 ls -l",
    "find /srv -type f | xargs grep foo",
    "find /tmp/build -type f | xargs rm",
    "git ls-files | xargs rm",
    "python3 -c 'print(1)'",
    "python3 -c \"import json; print(json.dumps({}))\"",
    "perl -e 'print 1'",
    "echo aGk= | base64 -d",
    "echo aGk= | base64 -d | cat",
    "rm -rf /tmp/$ZIEL",
    "rm -rf /tmp/build/$ZIEL",
    "cat ~/.claude/settings.json",
    "grep hooks ~/.claude/settings.json",
    "jq .hooks ~/.claude/settings.json",
    "ls ~/.claude/hooks",
    "cp ~/.claude/settings.json /tmp/settings.copy",
    "python3 ~/.claude/hooks/denylist_hook.py < /dev/null",
    "sed -n 1,5p ~/.claude/settings.json",
    "sed -i 's/a/b/' notes.txt",
    "echo hi > ~/.claude/notes.md",
    "rm ~/.claude/notes.md",
]


@pytest.mark.parametrize("cmd", DENIED_REVIEW_3)
def test_denied_review_3(cmd):
    assert decide(cmd, cwd=CWD) is not None, cmd


@pytest.mark.parametrize("cmd", ALLOWED_REVIEW_3)
def test_allowed_review_3(cmd):
    assert decide(cmd, cwd=CWD) is None, cmd


@pytest.mark.parametrize("cmd", ["rm -rf $ZIEL_UNGESETZT", "rm -rf \"$ZIEL_UNGESETZT\"", "rm -rf ${ZIEL}/sub",
                                 "rm -rf $(cat list)"])
def test_unset_variable_at_start_is_denied_even_under_scratch_cwd(cmd):
    assert decide(cmd, cwd="/var/tmp/work/proj") is not None, cmd
    assert decide(cmd, cwd="/tmp/work") is not None, cmd


def test_variable_inside_scratch_path_stays_allowed():
    assert decide("rm -rf /tmp/work/$NAME", cwd="/var/tmp/x") is None
