# IOTrap

Client side iotrap infrastructure to intercept and enhance IO performance

### Overview

The iotrap initiative aims at trapping the client side IO requests (currently
supports io_submit()) and sends them over multiple mounts (connections) over
NFS. The increased connections translates to an increase in network threads
available for the client. This allows us to achieve better throughput compared
to a single connection/thread

Performance improvement seen with READ over 10g network:
NFSv3 vanilla: 718mb/s
NFSv3 with iotrap: 1100mb/s
NFSv4 vanilla: 523mb/s
NFSv4 with iotrap: 1094mb/s

=> **Almost maxing out the network bandwidth with single 'fsperf' instance**

### Setup

- Download iotrap.so (say under: /root/iotrap.so)

- Mount the same volume (nfs_perf_rhelx01) from different data LIFs
  (preferably 4 LIFs), example (my test setup):

  ```
  172.17.90.32:/nfs_perf_rhelx01 on /root/hana/mnt/v32
  172.17.90.33:/nfs_perf_rhelx01 on /root/hana/mnt/v33
  172.17.90.34:/nfs_perf_rhelx01 on /root/hana/mnt/v34
  172.17.90.35:/nfs_perf_rhelx01 on /root/hana/mnt/v35
  ```

- All the data LIFs can be on the same port on the filer (so that they use the
  same network interface), example:

  | vserver | data LIF           | home-port | address      |
  | ------- | ------------------ | --------- | ------------ |
  | vs0     | nfs-f8060x05_data1 | e4a       | 172.17.90.32 |
  | vs0     | nfs-f8060x05_data2 | e4a       | 172.17.90.33 |
  | vs0     | nfs-f8060x05_data3 | e4a       | 172.17.90.34 |
  | vs0     | nfs-f8060x05_data4 | e4a       | 172.17.90.35 |

- On the client side, in the shell you intend to run the tests:
  Set environment variable IOTRAP_MOUNT_POOLS (some_name:comma,separated,mount,paths):

  ```shell
  $ export IOTRAP_MOUNT_POOLS="e4a:/root/hana/mnt/v32/,/root/hana/mnt/v33/,/root/hana/mnt/v34/,/root/hana/mnt/v35/ e4b:/root/hana/mnt/v42/,/root/hana/mnt/v43/,/root/hana/mnt/v44/,/root/hana/mnt/v45/ e3a:/root/hana/mnt/v52/,/root/hana/mnt/v53/,/root/hana/mnt/v54/,/root/hana/mnt/v55/ e3b:/root/hana/mnt/v62/,/root/hana/mnt/v63/,/root/hana/mnt/v64/,/root/hana/mnt/v65/"
  ```

- Intercepted funcations can be traced by setting IOTRAP_TRACE environment variable. To stop tracking,
  unset the environment variable and run the app

### Running the SAP Hana 'fsperf' test under GNU/Linux

#### Without the iotrap improvements
```shell
$ echo 3 > /proc/sys/vm/drop_caches
$ ./fsperf -t read -m throughput -f 2g -b 64k -o short --noinit /root/hana/mnt/v32/
```



#### With iotrap based improvements

```shell
$ echo 3 > /proc/sys/vm/drop_caches
$ LD_PRELOAD=/root/iotrap.so ./fsperf -t read -m throughput -f 2g -b 64k -o short --noinit /root/hana/mnt/v32/
```