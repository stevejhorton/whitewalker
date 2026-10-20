hostname=`hostname`
user=`whoami`

echo "SENT: <133>$(date '+%b %e %H:%M:%S') testhost CPR-test: action=test_shot machine=\"$hostname\" user=\"$user\" msg=\"hello from bash\""
echo "<133>$(date '+%b %e %H:%M:%S') testhost CPR-test: action=test_shot machine=\"$hostname\" user=\"$user\" msg=\"hello from bash\"" | nc -u -w1 cpr-syslog.uhc.com 514
