echo "Cleaning up and to start new build.."
rm -rf CPR/
rm -rf .tmp/
git pull
./roll_cpr_package.sh


