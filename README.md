# icsx-corpus

To generate feature files for VPN-NonVPN flow content characterization:

Download the ICSX VPN-NonVPN PCAPs from  https://www.unb.ca/cic/datasets/vpn.html

On any Linux machine with wireshark installed, run:

```
scripts/generate.sh /path/to/ICSX  /output/directory
``` 

This will write flows as numpy arrays in indexed HDFS-5 (.h5) files with associated category labels for
use in ML experiments.
