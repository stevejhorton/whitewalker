hostname=`hostname`
user=`whoami`
machine="CPR_TESTER"
evt=$(date -Iseconds)
msg="<133>$(date '+%b %e %H:%M:%S') $hostname CPR-test: action=\"test_shot\" machine=\"$machine\" user=\"$user\" EvtTime=\"$evt\" msg=\"hello from bash\" note=\"src_host=$hostname\""

echo "SENT: $msg"
echo "$msg" | nc -u -w1 cpr-syslog.uhc.com 514
