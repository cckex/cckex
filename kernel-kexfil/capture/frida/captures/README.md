# CCKex: Capture Scripts

# Capture

Once the Emulator and Signal are up and running, the following scripts can invoke the manual or automatic test captures of the CCKex Framework. These tests are called 'capture tests' because these tests aim to gather network traffic captures with payload data in covert channels in the traffic. After each test capture, the scripts automatically create a dump directory containing the test artifacts in the `eval/` directory. The artifacts of the latest test are also always copied to the `eval/current` directory to allow an easier configuration of the CCKex Wireshark Plugin.

The following test scripts are available:
- `new_manual_capture.sh`: Used to perform a manual capture test with the AVD. 'Manual' refers to 'manually typing the messages'. This script is also used in the `run-demo` target of the [kernel-kexfil Makefile](kernel-kexfil/README.md)
- `new_capture.sh`: Used to perform an automatic capture test with the AVD.
- `hardware_capture.sh`: Used to perform an automatic capture test with an actual device.

The basic flow of a capture test script is as follows:
- Reset the LKM to delete previously staged payload data (`ccsetup -r`).
- Enable different covert channel injection methods of the LKM. The injection methods can be altered by commenting/uncommenting the `ccsetup -ecc ...` calls at the top of the capture scripts.
- Set up a system log dump to a file (see `cap.dmesg` in the [Evaluation](#evaluation) section).
- Set up a on-device traffic capture (see `_cap.pcap` in the [Evaluation](#evaluation) section).
- In the case of automatic tests: Set up appium.
- Temporarily disable SELinux to enable the CCKex Framework to write to the `/dev/cc_kex` chardev.
- Start the modified friTap utility and _invoke the Signal App through friTap_ to start the automatic TLS Key dumping.
- Start the [`signal_injector.js`](kernel-kexfil/capture/frida/scripts/signal_injector/signal_injector.js) script to start the automatic Signal E2EE Key exfiltration and dumping.
- __In the case of automatic tests__: Start a [appium script](kernel-kexfil/capture/appium). The respective script can be changed by commenting/uncommenting.
- __In the case of manual tests__: The execution of the capture script will hang here until the user closes Signal.
- Reenable SELinux.
- Retrieve the on-device traffic capture.
- Kill all subprocesses.
- Invoke the `cleanup.sh` script. This will move all test artifacts to the dump/current folder in the `eval` directory.

Even though an on-device capture file `_cap.pcap` is created in these capture tests, any network capture of the traffic can be used. E.g., a local Wireshark instance can capture the docker network interface or a WIFI access point used by the real Google Pixel. However, be aware that the virtual network interface used by docker may behave differently than real hardware, e.g., resetting reserved fields of packages back to zero (this would cause a covert channel, leveraging these reserved fields, not to work anymore).

The following files are considered legacy and are currently not used anymore:
- `capture.sh`
- `extract_encrypted_message.sh`
- `pkg_decrypt/`
- `Makefile`
- `parse_logcat_output.sh`

# Evaluation

Every capture test creates test artifacts, which are moved to the `eval/current` and `eval/<timestamp>-dump` folders. The `eval/current` folder can be used to easily configure the CCKex Wireshark Plugin to always use the most current test artifacts. The following files are commonly created test artifacts:
-`_cap.pcap`: On-device network traffic capture. Backup and replace this file with your own capture file if you want to use a different capturing scenario.
- `backup_cap.key`: This is a backup of the TLS Keys used by Signal to encrypt the E2EE traffic. It can be used to decrypt the Signal TLS Layer, e.g., if the TLS Key exfiltration via the LKM failes or for debugging reasons.
- `cap.keylist`: This is a backup of the exfiltrated Signal E2EE Keys. The Plugin can use them to decrypt the Signal E2EE traffic, e.g., if the E2EE Key exfiltration fails or for debugging reasons.
- `cap.logcat`: Legacy file containing a dump of the Android `logcat` program. It is not used anymore.
- `cap.dmesg`: Dump of the sysem log while the capture was executed. This can be used for debugging errors/behaviour of the LKM after the capture.

Note that in a real scenario where the CCKex Framework is correctly configured and used, only the network traffic capture is needed to decrypt the Signal E2EE traffic (e.g., see the [example](kernel-kexfil/capture/frida/captures/example/_cap.pcap). 

By using the CCKex Wireshark Plugin, two additional files may be generated in the `eval/current` directory (if the Plugin is configured to point to this directory)
- `cap.key`: This file contains the exfiltrated TLS Keys and is available after dumping the TLS Keys via the Plugin. This file should be identical with `backup_cap.key`.
- `stats_dump.csv`: This file is created after dumping the CCKex Stats via the Plugin.
