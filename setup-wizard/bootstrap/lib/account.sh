# Parent/admin account creation and child-account topology enforcement
# (issue #16). Sourced by omarchy-kids-bootstrap, not run standalone.
#
# Account topology (see docs/agent-protocol.md "Account topology"):
# agentd/agent/omarchy-kids-run all run as the CHILD's own account, which
# must therefore not be a polkit admin. A separate account carries admin
# rights instead, so the PIN/polkit override path (agent issue #9) has
# something meaningful to authenticate against. Naming convention: follows
# every other omarchy-kids-* binary/account name in this repo.
# shellcheck disable=SC2034  # consumed by omarchy-kids-bootstrap, which sources this file
OMARCHY_KIDS_ADMIN_USER_DEFAULT="omarchy-kids-parent"

# create_parent_admin_account <child_user> <admin_user> <admin_password>
#
# Creates (or updates) the admin account and makes sure the child's own,
# Omarchy-created account is not in `wheel` — Omarchy's own first-boot
# flow makes the primary user a sudoer by default, which is exactly the
# membership this function has to undo.
create_parent_admin_account() {
  local child_user="$1" admin_user="$2" admin_password="$3"

  if ! id "$admin_user" >/dev/null 2>&1; then
    useradd -m -G wheel -s /bin/bash "$admin_user"
  elif ! id -nG "$admin_user" | tr ' ' '\n' | grep -qx wheel; then
    usermod -aG wheel "$admin_user"
  fi
  # An empty password means "leave an existing account's password alone" (the
  # caller only passes one for a new account or when the parent asked for it).
  if [[ -n $admin_password ]]; then
    echo "$admin_user:$admin_password" | chpasswd
  fi

  # Being in `wheel` is not enough on Omarchy: its wheel rules are narrow
  # NOPASSWD ones for specific commands, so without this the admin account
  # could not run sudo pacman, systemctl, and so on.
  grant_admin_sudo "$admin_user"

  if id -nG "$child_user" | tr ' ' '\n' | grep -qx wheel; then
    gpasswd -d "$child_user" wheel >/dev/null
    echo "omarchy-kids-bootstrap: removed '$child_user' from wheel (child accounts must not be polkit admins)" >&2
  fi
}

# grant_getty_lockdown_sudo <child_user>
#
# omarchy-kids-set-tier (tiers/omarchy-kids-set-tier) masks the unused VTs
# via `sudo systemctl mask --now getty@tty2..6.service` — the actual
# access-control boundary for the kiosk tiers (see root CLAUDE.md). That
# call runs as whichever account invokes the tier switch, which after this
# script's wheel fix-up above is the child account with NO sudo rights at
# all, and even before that fix-up a non-interactive sudo call has no tty to
# prompt on. Either way the mask step would silently no-op (the script
# swallows its result with `|| true`), quietly disabling VT lockdown.
#
# Fixes it the same way Omarchy's own first-boot setup already does for
# other commands (see its create_user(): "omarchy ships narrow %wheel
# NOPASSWD rules for specific commands") — a narrow NOPASSWD grant for
# exactly this command, not a return to broad admin rights.
#
# Filename sorts last on purpose (verified against a real conflict in the
# dev VM: a pre-existing `devchild ALL=(ALL) ALL` in /etc/sudoers.d/04_devchild
# alphabetically outranked an earlier "00-" filename here and silently
# shadowed this NOPASSWD grant — sudoers uses last-match-wins per exact
# command line, regardless of which rule is narrower). A "zz-" prefix keeps
# this grant authoritative no matter what other rules exist for the account.
grant_getty_lockdown_sudo() {
  local child_user="$1"
  local sudoers_file="${OMARCHY_KIDS_SUDOERS_DIR:-/etc/sudoers.d}/zz-omarchy-kids-getty-lockdown"
  local getty_units="getty@tty2.service getty@tty3.service getty@tty4.service getty@tty5.service getty@tty6.service"
  local tmp_file

  tmp_file="$(mktemp)"
  {
    echo "$child_user ALL=(root) NOPASSWD: /usr/bin/systemctl mask --now $getty_units"
    echo "$child_user ALL=(root) NOPASSWD: /usr/bin/systemctl unmask $getty_units"
  } > "$tmp_file"

  visudo -c -f "$tmp_file" >/dev/null
  install -m 440 "$tmp_file" "$sudoers_file"
  rm -f "$tmp_file"
}

# grant_admin_sudo <admin_user>
#
# Full sudo for the parent/admin account, in its own validated sudoers file.
# `visudo -c` checks the file before it goes live (a broken sudoers file can
# lock everyone out). Filename sorts last like the other grants.
grant_admin_sudo() {
  local admin_user="$1"
  local sudoers_file="${OMARCHY_KIDS_SUDOERS_DIR:-/etc/sudoers.d}/zz-omarchy-kids-admin"
  local tmp_file

  tmp_file="$(mktemp)"
  echo "$admin_user ALL=(ALL:ALL) ALL" > "$tmp_file"
  visudo -c -f "$tmp_file" >/dev/null
  install -m 440 "$tmp_file" "$sudoers_file"
  rm -f "$tmp_file"
}

# grant_tier_apply_sudo <child_user>
#
# omarchy-kids-set-tier runs as the child and, for tiers that ship a
# systemd/ folder, installs the autonomous-update timer with `sudo install`
# and `sudo systemctl enable`. With the child's own full-sudo rule removed
# (revoke_child_full_sudo), those calls need narrow grants of their own —
# exact command lines only, generated per tier folder that ships the unit
# files. No wildcards: a `*` in a sudoers argument also matches `../`, which
# would let the child install any file as root.
grant_tier_apply_sudo() {
  local child_user="$1"
  local sudoers_file="${OMARCHY_KIDS_SUDOERS_DIR:-/etc/sudoers.d}/zz-omarchy-kids-tier-update"
  local tiers_dir="${OMARCHY_KIDS_TIERS_DIR:-/usr/lib/omarchy-kids/tiers}"
  local tmp_file tier_dir

  tmp_file="$(mktemp)"
  for tier_dir in "$tiers_dir"/*/; do
    [[ -f "${tier_dir}systemd/omarchy-kids-update.service" ]] || continue
    tier_dir="${tier_dir%/}"
    echo "$child_user ALL=(root) NOPASSWD: /usr/bin/install -Dm644 $tier_dir/systemd/omarchy-kids-update.service /etc/systemd/system/omarchy-kids-update.service" >> "$tmp_file"
    echo "$child_user ALL=(root) NOPASSWD: /usr/bin/install -Dm644 $tier_dir/systemd/omarchy-kids-update.timer /etc/systemd/system/omarchy-kids-update.timer" >> "$tmp_file"
  done
  echo "$child_user ALL=(root) NOPASSWD: /usr/bin/systemctl enable --now omarchy-kids-update.timer" >> "$tmp_file"

  visudo -c -f "$tmp_file" >/dev/null
  install -m 440 "$tmp_file" "$sudoers_file"
  rm -f "$tmp_file"
}

# revoke_child_full_sudo <child_user>
#
# Omarchy's installer gives the account it creates (the child's) its own full
# sudo rule, in a file like /etc/sudoers.d/04_<user>. Taking the child out of
# `wheel` does not touch that, so without this the child keeps full admin
# rights and the lockdown means nothing. Deletes such a file only when its
# ONLY rule is that full grant, after saving a copy; anything more complex is
# reported for the parent to edit by hand, never rewritten here. Our own
# zz-omarchy-kids-* files are never touched.
revoke_child_full_sudo() {
  local child_user="$1"
  local sudoers_dir="${OMARCHY_KIDS_SUDOERS_DIR:-/etc/sudoers.d}"
  local main_sudoers="${OMARCHY_KIDS_SUDOERS_MAIN:-/etc/sudoers}"
  local backup_dir="${OMARCHY_KIDS_SUDOERS_BACKUP_DIR:-/root/omarchy-kids-sudoers-backup}"
  local full_rule_re="^${child_user}[[:space:]]+ALL[[:space:]]*=[[:space:]]*\\(ALL(:ALL)?\\)[[:space:]]+ALL\$"
  local file rules

  for file in "$sudoers_dir"/*; do
    [[ -f $file ]] || continue
    [[ $(basename "$file") == zz-omarchy-kids-* ]] && continue
    rules="$(grep -vE '^[[:space:]]*(#|$)' "$file" || true)"
    grep -qE "$full_rule_re" <<<"$rules" || continue
    if [[ $(grep -c . <<<"$rules") -eq 1 ]]; then
      install -d -m 700 "$backup_dir"
      cp -p "$file" "$backup_dir/"
      rm -f "$file"
      echo "omarchy-kids-bootstrap: removed '$file' (it gave '$child_user' full sudo; copy kept in $backup_dir)" >&2
    else
      echo "omarchy-kids-bootstrap: WARNING — '$file' gives '$child_user' full sudo among other rules; edit it by hand" >&2
    fi
  done

  if [[ -f $main_sudoers ]] && grep -qE "$full_rule_re" "$main_sudoers"; then
    echo "omarchy-kids-bootstrap: WARNING — '$main_sudoers' gives '$child_user' full sudo; edit it by hand (visudo)" >&2
  fi
}

# generate_admin_password
#
# Phase 1 has no UI yet (see the vault note's phasing) — the parent-facing
# form that will actually prompt for this interactively is issue #27. Until
# then: accept an explicit --admin-password, or generate and print one once
# so the script stays usable non-interactively in the dev VM.
generate_admin_password() {
  openssl rand -base64 18
}
