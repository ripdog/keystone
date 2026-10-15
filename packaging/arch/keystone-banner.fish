# Keystone console login banner for fish (sourced from vendor_conf.d).
# Opt out with: touch /etc/keystone/no-banner
if status is-login; and status is-interactive; and test -t 1
    if not test -e /etc/keystone/no-banner; and not set -q KEYSTONE_BANNER_SHOWN; and command -q keystonectl
        set -gx KEYSTONE_BANNER_SHOWN 1
        timeout 3 keystonectl banner 2>/dev/null
    end
end
