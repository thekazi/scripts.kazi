#!/usr/bin/env bash
#
# imperium-password-reset.sh
#
# Resets the WordPress password for a single WP account across every
# application under /home/master/applications/*/public_html.
#
# Each reset runs as the application's OWN system user (folder name == user),
# in a login shell, AFTER cd-ing into the docroot. The cd is required because
# these installs load salts from a separate wp-salt.php via a RELATIVE path,
# which only resolves when the working directory is the docroot (--path alone
# is not enough). Passwords are NOT recorded.
#
# Run as root (or via sudo): it needs 'sudo -u <appuser>'.
#
set -uo pipefail

# ---- Config -----------------------------------------------------------------
APPS_ROOT="/home/master/applications"
WP_USER="support@imperium.social"      # WP account to reset (login or email)
# -----------------------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run this as root (or with sudo). It needs 'sudo -u <appuser>'." >&2
    exit 1
fi

shopt -s nullglob

# Run a wp command as the app user, from inside the docroot, in a login shell.
run_wp() {
    local app="$1" docroot="$2"; shift 2
    sudo -u "${app}" -H -- bash -lc "cd '${docroot}' && $*"
}

total=0; ok=0; skipped=0

for appdir in "${APPS_ROOT}"/*/; do
    app="$(basename "${appdir}")"
    docroot="${appdir}public_html"
    total=$((total + 1))

    # 1) The system user must exist, otherwise 'sudo -u' cannot run.
    if ! getent passwd "${app}" >/dev/null 2>&1; then
        echo "SKIP  ${app}: no system user by that name" >&2
        skipped=$((skipped + 1)); continue
    fi

    # 2) The document root must exist.
    if [[ ! -d "${docroot}" ]]; then
        echo "SKIP  ${app}: ${docroot} not found" >&2
        skipped=$((skipped + 1)); continue
    fi

    # 3) It must be a reachable WordPress install.
    if ! run_wp "${app}" "${docroot}" "wp core is-installed" >/dev/null 2>&1; then
        echo "SKIP  ${app}: WordPress not installed / not reachable at ${docroot}" >&2
        skipped=$((skipped + 1)); continue
    fi

    # 4) The target WP user must be present in THIS install.
    if ! run_wp "${app}" "${docroot}" "wp user get '${WP_USER}' --field=ID" >/dev/null 2>&1; then
        echo "SKIP  ${app}: WP user '${WP_USER}' not present" >&2
        skipped=$((skipped + 1)); continue
    fi

    # 5) Reset the password (random, not recorded; user not emailed).
    if run_wp "${app}" "${docroot}" "wp user reset-password '${WP_USER}' --skip-email" >/dev/null 2>&1; then
        echo "OK    ${app}: password reset"
        ok=$((ok + 1))
    else
        echo "FAIL  ${app}: reset-password returned an error" >&2
        skipped=$((skipped + 1))
    fi
done

echo "----"
echo "Processed: ${total}  Reset: ${ok}  Skipped/failed: ${skipped}"
