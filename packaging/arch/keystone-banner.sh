# Keystone console login banner. Sourced by login shells via /etc/profile.
# Opt out with: touch /etc/keystone/no-banner
case $- in *i*) ;; *) return 0 2>/dev/null || exit 0 ;; esac
[ -t 1 ] || return 0
[ -e /etc/keystone/no-banner ] && return 0
[ -n "$KEYSTONE_BANNER_SHOWN" ] && return 0
KEYSTONE_BANNER_SHOWN=1
if command -v keystonectl >/dev/null 2>&1; then
    timeout 3 keystonectl banner 2>/dev/null
fi
