#!/bin/zsh

set -euo pipefail
LDAP_URI='ldap://ms.ds.uhc.com'
BASE_DN='CN=Users,DC=ms,DC=ds,DC=uhc,DC=com'
GROUPS_FILE="${1:-groups.txt}"

# Logged-in console user (handles fast user switching better than $USER)
logged_in_user="$(stat -f '%Su' /dev/console)"
# If you need shortname explicitly, on most Macs this is already the shortname.
shortname="$logged_in_user"
# Pull memberOf once; return only memberOf values, no wrapping
memberOf_dns="$(
ldapsearch -LLL -H "$LDAP_URI" -b "$BASE_DN"
"(&(objectCategory=Person)(objectClass=User)(sAMAccountName=${shortname}))" memberOf | awk -F': ' '/^memberOf: /{print $2}')"
# Walk the GG list, echo matches
while IFS= read -r gg || [[ -n "$gg" ]]; do
# skip blanks/comments
[[ -z "$gg" || "$gg" == \#* ]] && continue
# match CN=GroupName, somewhere in the DN
if printf '%s\n' "$memberOf_dns" | grep -qiE "(^|,)CN=${gg//\./\\.}(,|$)"; then
echo "$gg"
fi
done < "$GROUPS_FILE"
