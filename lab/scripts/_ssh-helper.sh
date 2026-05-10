# sourced helper: provides $LAB_SSH_CONFIG and `lab_ssh <host> <cmd>`.
# Generated once per run via `vagrant ssh-config` to avoid Vagrant's
# stdin-stealing wrapper on Windows Git Bash that silently aborts the
# parent script after the second invocation.
LAB_SSH_CONFIG="${LAB_SSH_CONFIG:-/tmp/lab-ssh-config.$$.txt}"

lab_ssh_init() {
  if [[ ! -s "$LAB_SSH_CONFIG" ]]; then
    ( cd "$(dirname "${BASH_SOURCE[0]}")/../vagrant" && \
      vagrant ssh-config ) > "$LAB_SSH_CONFIG"
  fi
}

lab_ssh() {
  local host="$1"; shift
  # -n closes ssh's stdin so it can't consume the parent shell's input,
  # which on Git Bash causes the parent script to exit silently after
  # the second ssh call.
  ssh -F "$LAB_SSH_CONFIG" -o LogLevel=ERROR -n "$host" "$@"
}
