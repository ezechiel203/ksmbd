set -eu
for i in 1 2 3; do
    echo ITER:$i:BEGIN
    timeout 30 ksmbdctl stop
    echo ITER:$i:STOP_OK
    timeout 20 rmmod ksmbd
    echo ITER:$i:RMMOD_OK
    insmod /mnt/ksmbd/ksmbd.ko
    echo ITER:$i:INSMOD_OK
    ksmbdctl start
    echo ITER:$i:START_OK
    sleep 1
    pgrep -a -x ksmbdctl || true
    echo ITER:$i:END
 done
