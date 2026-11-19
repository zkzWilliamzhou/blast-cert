"""Generate blast/catalog.json from an auditable rule table.

Run: python3 tools/build_catalog.py
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "blast", "catalog.json")


def rule(rid: str, match: str, values: List[str], add: List[str],
         severity: str, reason: str) -> Dict[str, object]:
    return {
        "id": rid, "match": match, "values": values,
        "add": add, "severity": severity, "reason": reason,
    }


def command(family: str, operand: str, base: List[str],
            flags: Dict[str, List[str]] = None,
            value_flags: List[str] = None,
            arg_rules: List[Dict[str, object]] = None,
            positive: List[str] = None,
            negative: List[str] = None,
            opaque: List[str] = None) -> Dict[str, object]:
    return {
        "family": family,
        "operand_kind": operand,
        "base": base,
        "flags": flags or {},
        "value_flags": value_flags or [],
        "arg_rules": arg_rules or [],
        "tests": {
            "positive": positive or [],
            "negative": negative or [],
            "opaque": opaque or [],
        },
    }


READ = ["FS_READ"]
WRITE = ["FS_WRITE"]
DELETE = ["FS_DELETE"]
NET = ["NET_OUTBOUND"]

COMMANDS: Dict[str, Dict[str, object]] = {}


def add(name: str, spec: Dict[str, object]) -> None:
    COMMANDS[name] = spec


# --- coreutils: reading -------------------------------------------------
for name in ("cat", "head", "tail", "less", "more", "stat", "file", "wc",
             "strings", "od", "hexdump", "nl", "tac", "rev", "column",
             "readlink", "realpath", "basename", "dirname", "du", "df",
             "sha256sum", "sha1sum", "md5sum", "cksum", "sort", "uniq",
             "cut", "tr", "paste", "comm", "join", "tee", "yes"):
    add(name, command("coreutils", "path", READ,
                      flags={"-n": [], "-v": [], "-q": [], "-a": [], "-c": [],
                             "-b": [], "-e": [], "-s": [], "-r": [], "-l": [],
                             "-f": [], "-h": [], "-A": [], "-B": [], "-C": [],
                             "--all": [], "--bytes": [], "--lines": [],
                             "--help": [], "--version": [], "-z": [], "-u": [],
                             "-d": [], "-t": [], "-i": [], "-w": [], "-p": []},
                      positive=["%s /etc/hostname" % name],
                      negative=["%s --help" % name]))

add("ls", command("coreutils", "path", READ,
                  flags={"-l": [], "-a": [], "-A": [], "-h": [], "-R": [],
                         "-r": [], "-t": [], "-S": [], "-d": [], "-F": [],
                         "-i": [], "-n": [], "-s": [], "-1": [], "-Z": [],
                         "--all": [], "--long": [], "--human-readable": [],
                         "--recursive": [], "--help": [], "--version": []},
                  positive=["ls -la"], negative=["ls --help"]))
add("grep", command("coreutils", "path", READ,
                    flags={"-i": [], "-v": [], "-r": [], "-R": [], "-n": [],
                           "-E": [], "-F": [], "-q": [], "-l": [], "-c": [],
                           "-w": [], "-x": [], "-A": [], "-B": [], "-C": [],
                           "-e": [], "-f": [], "--color": [], "--help": []},
                    value_flags=["-e", "-f", "-A", "-B", "-C"],
                    positive=["grep -n foo README.md"]))
add("sed", command("coreutils", "path", READ,
                   flags={"-n": [], "-e": [], "-f": [], "-i": ["FS_WRITE"],
                          "-E": [], "-r": [], "-s": [], "--help": []},
                   value_flags=["-e", "-f"],
                   positive=["sed -n '1p' README.md"]))
add("awk", command("coreutils", "path", READ,
                   flags={"-F": [], "-f": [], "-v": [], "--help": []},
                   value_flags=["-F", "-f", "-v"],
                   positive=["awk '{print $1}' README.md"]))
add("jq", command("json", "path", READ,
                  flags={"-r": [], "-c": [], "-f": [], "-e": [], "-s": [],
                         "--arg": [], "--help": []},
                  value_flags=["-f", "--arg"], positive=["jq . package.json"]))
add("pwd", command("builtin", "none", [], positive=["pwd"], negative=["pwd --help"]))
for name in ("echo", "printf", "date", "id", "whoami", "true", "false", ":",
             "hostname", "uname", "uptime", "free", "sleep", "seq"):
    add(name, command("builtin", "none", [], positive=[name]))

# --- coreutils: writing and deleting ------------------------------------
add("rm", command("coreutils", "path", DELETE,
                  flags={"-r": ["FS_DELETE_RECURSIVE"], "-R": ["FS_DELETE_RECURSIVE"],
                         "--recursive": ["FS_DELETE_RECURSIVE"], "-f": [],
                         "--force": [], "-i": [], "-v": [], "-d": [],
                         "--no-preserve-root": ["FS_DESTRUCTIVE"],
                         "--preserve-root": [], "--one-file-system": [],
                         "--help": [], "--version": [], "--": []},
                  arg_rules=[rule("rm.root_operand", "any_arg",
                                  ["/", "~", "/*", "/.", "/.."],
                                  ["FS_DESTRUCTIVE"], "critical",
                                  "recursive delete targets a filesystem root")],
                  positive=["rm -rf /tmp/x"], negative=["rm --version"],
                  opaque=["rm $TARGET"]))
add("rmdir", command("coreutils", "path", DELETE,
                     flags={"-p": [], "-v": [], "--help": []},
                     positive=["rmdir /tmp/x"]))
add("find", command("coreutils", "path", READ,
                    flags={"-type": [], "-name": [], "-iname": [], "-path": [],
                           "-delete": ["FS_DELETE"], "-exec": ["CODE_EXEC_OPAQUE"],
                           "-ok": ["CODE_EXEC_OPAQUE"], "-print": [],
                           "-print0": [], "-maxdepth": [], "-mindepth": [],
                           "-size": [], "-mtime": [], "-newer": [], "-user": [],
                           "-group": [], "-perm": [], "-empty": [], "-not": [],
                           "!": [], "-o": [], "-a": [], "-regex": [],
                           "-regextype": [], "-L": [], "-H": [], "-P": [],
                           "--help": []},
                    value_flags=["-type", "-name", "-iname", "-path", "-exec",
                                 "-ok", "-maxdepth", "-mindepth", "-size",
                                 "-mtime", "-newer", "-user", "-group", "-perm",
                                 "-regex", "-regextype"],
                    positive=["find /var/log -type f -delete"],
                    negative=["find . -name '*.py' -print"],
                    opaque=["find $DIR -delete"]))
add("cp", command("coreutils", "path", WRITE,
                  flags={"-r": [], "-R": [], "-a": [], "-f": [], "-i": [],
                         "-v": [], "-p": [], "-u": [], "-n": [], "-L": [],
                         "-P": [], "-T": [], "--help": [], "--": []},
                  positive=["cp a.txt b.txt"]))
add("mv", command("coreutils", "path", WRITE + DELETE,
                  flags={"-f": [], "-i": [], "-n": [], "-v": [], "-u": [],
                         "-T": [], "--help": [], "--": []},
                  positive=["mv a.txt b.txt"]))
add("touch", command("coreutils", "path", WRITE,
                     flags={"-a": [], "-m": [], "-c": [], "-t": [], "-d": [],
                            "-r": [], "--help": []},
                     value_flags=["-t", "-d", "-r"], positive=["touch /tmp/x"]))
add("mkdir", command("coreutils", "path", WRITE,
                     flags={"-p": [], "-m": [], "-v": [], "--help": []},
                     value_flags=["-m"], positive=["mkdir -p build"]))
add("chmod", command("coreutils", "path", ["FS_CHMOD"],
                     flags={"-R": ["FS_DELETE_RECURSIVE"], "-v": [], "-c": [],
                            "-f": [], "--reference": [], "--help": []},
                     value_flags=["--reference"],
                     positive=["chmod -R 777 /etc"]))
add("chown", command("coreutils", "path", ["FS_CHOWN"],
                     flags={"-R": ["FS_DELETE_RECURSIVE"], "-v": [], "-c": [],
                            "-f": [], "-h": [], "--help": []},
                     positive=["chown -R 0:0 /home"]))
add("chgrp", command("coreutils", "path", ["FS_CHOWN"],
                     flags={"-R": [], "-v": [], "-c": [], "-f": [], "--help": []},
                     positive=["chgrp staff /tmp/x"]))
add("ln", command("coreutils", "path", WRITE,
                  flags={"-s": [], "-f": [], "-n": [], "-v": [], "--help": []},
                  positive=["ln -s a b"]))
add("truncate", command("coreutils", "path", ["FS_TRUNCATE"] + WRITE,
                        flags={"-s": [], "-c": [], "-o": [], "--help": []},
                        value_flags=["-s"],
                        positive=["truncate -s 0 /var/log/audit.log"]))
add("dd", command("coreutils", "path", WRITE,
                  flags={"--help": [], "--version": []},
                  arg_rules=[
                      rule("dd.device_write", "arg_prefix", ["of=/dev/", "of=/proc/",
                                                            "of=/sys/"],
                           ["FS_DEVICE_WRITE", "FS_DESTRUCTIVE"], "critical",
                           "dd writes directly to a device node"),
                      rule("dd.any_device", "arg_prefix", ["of="],
                           ["FS_WRITE"], "high", "dd writes an explicit output file"),
                  ],
                  positive=["dd if=/dev/zero of=/dev/sda bs=1M"]))
add("shred", command("coreutils", "path", DELETE,
                     flags={"-n": [], "-z": [], "-u": ["FS_DELETE"], "-f": [],
                            "-v": [], "-s": [], "--help": []},
                     value_flags=["-n", "-s"],
                     positive=["shred -n 3 -z -u /etc/secrets.key"]))
for name in ("mkfs", "mkfs.ext4", "mkfs.ext3", "mkfs.xfs", "mkfs.btrfs",
             "mkswap", "fdisk", "parted", "wipefs"):
    add(name, command("storage", "path", ["FS_DEVICE_WRITE", "FS_DESTRUCTIVE"],
                      flags={"-f": [], "-t": [], "-L": [], "-q": [], "-V": [],
                             "-y": [], "--help": []},
                      value_flags=["-t", "-L"],
                      positive=["%s /dev/sdb1" % name]))
add("mount", command("storage", "path", ["PRIVILEGE_ESCALATION"],
                     flags={"-t": [], "-o": [], "-a": [], "-r": [], "-w": [],
                            "-v": [], "--help": []},
                     value_flags=["-t", "-o"], positive=["mount /dev/sdb1 /mnt"]))
add("umount", command("storage", "path", ["PRIVILEGE_ESCALATION"],
                      flags={"-f": [], "-l": [], "-a": [], "-v": [], "--help": []},
                      positive=["umount /mnt"]))

# --- network -------------------------------------------------------------
add("curl", command("network", "network", NET,
                    flags={"-s": [], "-S": [], "-f": [], "-L": [], "-I": [],
                           "-X": [], "-H": [], "-d": [], "-o": [], "-O": [],
                           "-u": [], "-k": [], "-v": [], "-q": [], "--data": [],
                           "--header": [], "--request": [], "--output": [],
                           "--silent": [], "--location": [], "--fail": [],
                           "--insecure": [], "--help": [], "--version": []},
                    value_flags=["-X", "-H", "-d", "-o", "-u", "--data",
                                 "--header", "--request", "--output"],
                    positive=["curl -s https://example.com/x.sh"]))
add("wget", command("network", "network", NET,
                    flags={"-q": [], "-O": [], "-qO-": [], "-c": [], "-r": [],
                           "-N": [], "-nv": [], "--quiet": [],
                           "--output-document": [], "--help": []},
                    value_flags=["-O", "--output-document"],
                    positive=["wget -qO- http://example.com/x.sh"]))
for name in ("nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync",
             "telnet", "ftp", "ping", "traceroute", "dig", "nslookup", "host"):
    add(name, command("network", "network", NET,
                      flags={"-e": ["NET_FETCH_TO_EXEC"], "-l": ["NET_LISTEN"],
                             "-p": [], "-v": [], "-q": [], "-r": [], "-a": [],
                             "-n": [], "-P": [], "-i": [], "-L": [], "-R": [],
                             "-o": [], "-c": [], "-4": [], "-6": [],
                             "--help": []},
                      value_flags=["-e", "-p", "-i", "-o", "-L", "-R"],
                      positive=["%s example.com" % name]))
add("base64", command("encoder", "none", [],
                      flags={"-d": [], "--decode": [], "-e": [], "-w": [],
                             "-i": [], "--help": []},
                      value_flags=["-w"], positive=["echo aWQK | base64 -d | sh"]))
for name in ("xxd", "openssl", "uudecode", "gunzip", "gzip", "bunzip2",
             "unzip", "tar", "zip"):
    add(name, command("encoder", "path", READ,
                      flags={"-r": [], "-p": [], "-d": [], "-e": [], "-c": [],
                             "-f": [], "-v": [], "-x": [], "-t": [], "-z": [],
                             "-j": [], "-k": [], "-l": [], "-o": [], "-C": [],
                             "enc": [], "-base64": [], "-A": [], "-in": [],
                             "-out": [], "--help": []},
                      value_flags=["-C", "-f", "-o", "-in", "-out"],
                      positive=["%s --help" % name]))
add("python", command("interpreter", "path", READ,
                      flags={"-c": ["CODE_EVAL"], "-m": [], "-u": [], "-B": [],
                             "-": ["CODE_EXEC_OPAQUE"], "--help": [],
                             "--version": []},
                      value_flags=["-c", "-m"],
                      positive=["python -c 'print(1)'"],
                      opaque=["python -c \"$SHELLCODE\""]))
add("python3", command("interpreter", "path", READ,
                       flags={"-c": ["CODE_EVAL"], "-m": [], "-u": [], "-B": [],
                              "-": ["CODE_EXEC_OPAQUE"], "--help": [],
                              "--version": []},
                       value_flags=["-c", "-m"],
                       positive=["python3 -c 'print(1)'"],
                       opaque=["python3 -c \"$SHELLCODE\""]))
for name in ("perl", "ruby", "node", "php", "lua", "deno", "bun"):
    add(name, command("interpreter", "path", READ,
                      flags={"-e": ["CODE_EVAL"], "-c": ["CODE_EVAL"],
                             "-p": [], "-i": [], "-v": [], "--version": [],
                             "--help": []},
                      value_flags=["-e", "-c"],
                      positive=["%s --version" % name]))
for name in ("sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh"):
    add(name, command("interpreter", "path", READ,
                      flags={"-c": ["CODE_EVAL"], "-e": [], "-x": [], "-n": [],
                             "-v": [], "-l": [], "-i": [], "-s": [], "--help": [],
                             "--version": [], "-": []},
                      value_flags=["-c"],
                      positive=["%s script.sh" % name],
                      opaque=["bash -c \"$SHELLCODE\""]))
for name in ("eval", "source", ".", "exec"):
    add(name, command("builtin", "path", ["CODE_EVAL", "CODE_EXEC_OPAQUE"],
                      positive=["%s /tmp/x" % name]))
add("xargs", command("coreutils", "none", ["CODE_EXEC_OPAQUE"],
                     flags={"-n": [], "-P": [], "-I": [], "-0": [], "-r": [],
                            "-t": [], "--help": []},
                     value_flags=["-n", "-P", "-I"],
                     positive=["ls | xargs cat"]))

# --- privilege, scheduling, persistence ---------------------------------
for name in ("sudo", "su", "doas", "pkexec"):
    add(name, command("privilege", "none", ["PRIVILEGE_ESCALATION"],
                      flags={"-u": [], "-l": [], "-n": [], "-s": [], "-i": [],
                             "-v": [], "-E": [], "-H": [], "-b": [], "-c": [],
                             "--help": []},
                      value_flags=["-u", "-c"],
                      positive=["sudo chmod -R 777 /etc"]))
add("nohup", command("scheduler", "none", ["PERSISTENCE"],
                     flags={"--help": []}, positive=["nohup /tmp/x &"]))
for name in ("crontab", "at", "systemctl", "launchctl", "service"):
    add(name, command("scheduler", "none", ["PERSISTENCE"],
                      flags={"-l": [], "-e": [], "-r": [], "-u": [], "-i": [],
                             "-f": [], "-m": [], "-b": [], "-c": [], "-": [],
                             "enable": [], "disable": [], "start": [],
                             "stop": [], "restart": [], "--now": [],
                             "--user": [], "--help": []},
                      value_flags=["-u", "-f", "-c"],
                      positive=["echo '@reboot bash /tmp/x' | crontab -"]))
add("export", command("builtin", "none", ["ENV_MUTATION"],
                      positive=["export LD_PRELOAD=/tmp/lib.so"]))
add("unset", command("builtin", "none", ["ENV_MUTATION"], positive=["unset FOO"]))
add("alias", command("builtin", "none", ["CODE_DYNAMIC_DISPATCH"],
                     positive=["alias rm='rm -i'"]))
add("unalias", command("builtin", "none", ["CODE_DYNAMIC_DISPATCH"],
                       flags={"-a": []}, positive=["unalias -a"]))
add("set", command("builtin", "none", ["ENV_MUTATION"],
                   flags={"-e": [], "-u": [], "-x": [], "-o": [], "-a": [],
                          "+e": [], "+x": [], "--": []},
                   positive=["set -e"]))
add("umask", command("builtin", "none", ["ENV_MUTATION"], positive=["umask 022"]))
add("ulimit", command("builtin", "none", ["RESOURCE_EXHAUSTION"],
                      flags={"-a": [], "-n": [], "-u": [], "-f": [], "-c": [],
                             "-v": [], "-t": [], "-s": []},
                      positive=["ulimit -n 1024"]))
add("history", command("builtin", "none", READ,
                       flags={"-c": ["EVIDENCE_DESTROY"], "-d": [], "-a": [],
                              "-w": [], "-r": []},
                       positive=["history -c"]))
add("mkfifo", command("coreutils", "path", WRITE, positive=["mkfifo /tmp/p"]))
add("timeout", command("coreutils", "none", [],
                       flags={"-s": [], "-k": [], "--help": []},
                       value_flags=["-s", "-k"],
                       positive=["timeout 5 ls"]))
add("env", command("coreutils", "none", ["ENV_MUTATION"],
                   flags={"-i": [], "-u": [], "-0": [], "--help": []},
                   value_flags=["-u"], positive=["env FOO=bar ls"]))

# --- version control, containers, cloud, databases, packages ------------
add("git", command("vcs", "path", ["VCS_READ"],
                   flags={"--force": ["VCS_HISTORY_REWRITE"],
                          "-f": ["VCS_HISTORY_REWRITE"],
                          "--force-with-lease": ["VCS_HISTORY_REWRITE"],
                          "--hard": ["FS_DELETE"],
                          "-d": [], "-D": ["FS_DELETE"], "-a": [], "-m": [],
                          "-v": [], "-q": [], "-b": [], "-B": [], "-u": [],
                          "--all": [], "--tags": [], "--prune": [], "-p": [],
                          "--no-verify": [], "--amend": [], "--help": [],
                          "--version": [], "-s": [], "-S": [], "-i": []},
                   value_flags=["-m", "-b", "-B", "-u", "-S"],
                   positive=["git status"], negative=["git status"],
                   opaque=["git push --force origin main"]))
add("docker", command("container", "selector", ["CLOUD_STATE_BULK"],
                      flags={"-f": [], "--force": [], "-a": [], "--all": [],
                             "-q": [], "--quiet": [], "--volumes": ["CLOUD_STATE_BULK"],
                             "-v": [], "-p": [], "-d": [], "-i": [], "-t": [],
                             "--rm": [], "--no-cache": [], "--help": [],
                             "--version": []},
                      value_flags=["-p", "-v", "-e", "--name"],
                      positive=["docker system prune -af --volumes"]))
add("kubectl", command("container", "selector", ["CLOUD_STATE_BULK"],
                       flags={"--all": ["CLOUD_STATE_BULK"],
                              "--all-namespaces": ["CLOUD_STATE_BULK"],
                              "--force": ["CLOUD_STATE_BULK"],
                              "--grace-period=0": ["CLOUD_STATE_BULK"],
                              "-f": [], "-l": [], "-n": [], "-o": [],
                              "--namespace": [], "--help": []},
                       value_flags=["-f", "-l", "-n", "-o", "--namespace"],
                       positive=["kubectl delete pod --all --all-namespaces"]))
add("terraform", command("cloud", "selector", ["CLOUD_STATE_BULK"],
                         flags={"destroy": ["CLOUD_STATE_BULK"], "-auto-approve": [],
                                "-force": [], "-var": [], "--help": []},
                         value_flags=["-var"],
                         positive=["terraform destroy -auto-approve"]))
add("psql", command("database", "sql", ["DB_DESTRUCTIVE"],
                    flags={"-c": [], "-f": [], "-h": [], "-p": [], "-U": [],
                           "-d": [], "-v": [], "-q": [], "-A": [], "-t": [],
                           "--help": []},
                    value_flags=["-c", "-f", "-h", "-p", "-U", "-d", "-v"],
                    arg_rules=[rule("psql.drop", "any_arg_contains",
                                    ["DROP DATABASE", "DROP TABLE", "TRUNCATE",
                                     "DELETE FROM"],
                                    ["DB_DESTRUCTIVE"], "critical",
                                    "SQL statement destroys database state")],
                    positive=["psql -c \"DROP DATABASE prod\""]))
add("mysql", command("database", "sql", ["DB_DESTRUCTIVE"],
                     flags={"-e": [], "-h": [], "-P": [], "-u": [], "-p": [],
                            "-D": [], "--help": []},
                     value_flags=["-e", "-h", "-P", "-u", "-D"],
                     arg_rules=[rule("mysql.drop", "any_arg_contains",
                                     ["DROP DATABASE", "DROP TABLE", "TRUNCATE",
                                      "DELETE FROM"],
                                     ["DB_DESTRUCTIVE"], "critical",
                                     "SQL statement destroys database state")],
                     positive=["mysql -e \"DELETE FROM users WHERE 1=1\""]))
add("sqlite3", command("database", "path", ["DB_DESTRUCTIVE"],
                       flags={"-batch": [], "-init": [], "-cmd": [],
                              "--help": []},
                       value_flags=["-init", "-cmd"],
                       positive=["sqlite3 db.sqlite 'DROP TABLE users'"]))
for name in ("npm", "yarn", "pnpm", "pip", "pip3", "apt", "apt-get", "yum",
             "dnf", "brew", "gem", "cargo", "go", "composer", "poetry"):
    add(name, command("package", "package", ["PACKAGE_MUTATION"],
                      flags={"-g": [], "--global": [], "-y": [], "--yes": [],
                             "-f": [], "--force": [], "-D": [], "-S": [],
                             "-U": [], "-O": [], "-q": [], "-v": [], "-e": [],
                             "install": [], "uninstall": [], "remove": [],
                             "purge": [], "update": [], "upgrade": [],
                             "clean": [], "cache": [], "--help": [],
                             "--version": []},
                      positive=["%s --help" % name]))
add("make", command("build", "path", READ,
                    flags={"-j": [], "-C": [], "-f": [], "-n": [], "-B": [],
                           "-s": [], "--help": []},
                    value_flags=["-j", "-C", "-f"], positive=["make -j2"]))
for name in ("gcc", "cc", "clang", "g++", "rustc", "javac", "java", "tsc"):
    add(name, command("build", "path", READ,
                      flags={"-o": [], "-c": [], "-g": [], "-O": [], "-Wall": [],
                             "-I": [], "-L": [], "-l": [], "--help": [],
                             "--version": []},
                      value_flags=["-o", "-I", "-L", "-l"],
                      positive=["%s --help" % name]))

# --- unknown command default -------------------------------------------
COMMANDS["__default__"] = {
    "family": "unknown",
    "operand_kind": "none",
    "base": ["CODE_EXEC_OPAQUE", "UNKNOWN_EFFECT"],
    "flags": {},
    "value_flags": [],
    "arg_rules": [],
    "tests": {"positive": ["madeup --flag"], "negative": [], "opaque": []},
}


def build() -> Dict[str, object]:
    return {
        "schema_version": 1,
        "version": "0.1.0",
        "commands": COMMANDS,
    }


def main() -> None:
    data = build()
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(data, handle, sort_keys=True, indent=2, ensure_ascii=False)
        handle.write("\n")
    print("wrote %s with %d command specs" % (OUT, len(COMMANDS)))


if __name__ == "__main__":
    main()
