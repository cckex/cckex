# CCKex Wireshark Plugin

The CCKex Wireshark plugin enables Wireshark to decrypt and parse Signal E2EE Messages. The modus operandi of message decryption and dissection is as follows: First, the plugin tries to exfiltrate the TLS Key data from configured (in the CCKex config.json) classic covert channels. After exfiltration, the TLS Key data can be dumped into a file and reloaded by Wireshark as TLS Keys. Once Wireshark decrypts the Signal TLS traffic, the plugin can parse and decrypt the Signal E2EE traffic via the injected Signal E2EE Key material.

[[_TOC_]]

## Build

Currently, only the [Local Build](#local-build) is fully supported. [Docker Build](#docker-build) can build Wireshark (with the plugin) in Docker. However, the resulting executable cannot be run on the host system (due to differences in shared libraries). The container's X11 Forwarding is not working yet.

### Local Build

Before building the CCKex plugin for the first time, initialize the local build system with `make init_wireshark`. After initialization, the Wireshark can be built and run as follows:
- Run `make build_wireshark` to build Wireshark with the CCKex Plugin.
- Run `wireshark/build/run/wireshark` to execute the newly built Wireshark.
- After running Wireshark for the first time the CCKex Plugin must be configured. See the [Configuration](#configuration) section next.

### Docker Build

Before building the CCKex plugin for the first time, initialize the Docker build system with `make init`. After initialization, the Wireshark can be built and run as follows:
- Run `make build` to build Wireshark with the CCKex Plugin.

### Troubleshooting

Currently, it is not possible to mix the [Local Build](#local-build) and [Docker Build](#docker-build). 

When in doubt, whether a build fails due to artifacts or a misconfigured build system, execute `make reset` to revert all changes and reset the `wireshark` repository. Afterward, `make init` or `make init_wireshark` can be used to set up the Wireshark repository and build the system again.

If build errors occur due to implicit declarations, such as `tvb_get_uint8`, ensure that the `wireshark/` Submodule is up-to-date.

## Configuration

### config.json

Modify the plugin [config.json](kernel-kexfil/capture/frida/captures/configs/config.json) (or ideally copy and edit the copy). _Optional_ values can be modified or left unmodified.

- Section `ws`: The paths of this section ideally should point to the same directory of the `_cap.pcap` capture file ([see capture directory documentation](kernel-kexfil/capture/frida/captures/README.md)).
    - `tls_keylog_file`: Absolute path to the `cap.key` file.
    - `signal_key_file`: Absolute path to the `cap.keylist` file.
- Section `filter`: Pre-filters are applied before processing a package in the covert channel exfiltration dissector. The dissector only processes a packet if it satisfies the following filter conditions.
    - `src_ip`: IP of the target device on which CCKex runs and injects payload data into the network traffic. Set this to `10.0.2.16` for the [example file](kernel-kexfil/capture/frida/captures/example/_cap.pcap) to work.
    - `dst_ip` (_optional_): IP of a potential target destination (if CCKex would only inject payload data in traffic to a specific destination).
    - `src_port` (_optional_): Only process packets with a specific source port.
    - `dst_port` (_optional_): Only process packets with a specific destination port.
- Section `cc -> methods`:
    - Only edit the `active` fields in this array for the respective methods to be active. Activate only the `tcphdr_urgent` entry for the [example file](kernel-kexfil/capture/frida/captures/example/_cap.pcap) to work.
- Section `crypto`: This is a legacy option to decrypt covert channel payload data protected by encryption (encryption method `method`). **Always ensure that `enabled` is set to _false_ in this section**.

### Wireshark Settings

- Open Wireshark
- Go to `Edit -> Options -> Protocols -> CCKex`:
    - Set `Configuration File` to the previously created `config.json`
- Go to `Edit -> Options -> Protocols -> ProtoBuf`: 
    - Click on `Protobuf search paths`
    - Add the directory with the [Signal ProtoBuf](wireshark-plugin/protowire) files to the ProtoBuf Dissector's search paths
    - Select the `Load all files` checkbox.
- Apply and save the settings

## Usage

- Open `wireshark/build/run/wireshark`
- Open the network traffic dump with CCKex payload (use the [example dump](kernel-kexfil/capture/frida/captures/example/_cap.pcap) for testing)
- Use the `tls` display filter to show the Signal TLS traffic
- The `ccKex Exfiltration Dissector` should now already be visible in the Dissectors Tree
- Open the CCKex GUI via `Tools -> CCKex`
    - In the GUI click the `Dump TLS Keys to File` button
    - Reopen the pcap file or reload it via the `Reload File` butotn
- Apply the `websocket` display filter. If the TLS decryption was successful the decrypted Signal messages will be displayed and the CCKex dissectors will be available in the dissector tree:
    - `ccKex Signal Websocket Layer`: Dissects the websocket layer
    - `ccKex Signal Request Body`: Dissects the request body in the websocket request -> contains the decrypted `Envelope x` envelope sections
    - `Protocol Buffers: signalservice.Content`: Decrypted typing/text message with `body` field (containing the text message) and `cckex_msglvl_injection` field (containing the injected data)

### Troubleshooting

Some packages show the error `Malformed Packet: cckex.msg` in the dissection tree. This is caused by false-positive Signal E2EE messages. They are recognized as E2EE messages but do not contain an encrypted sealed sender block.

## Documentation

### Makefile

Available targets are:
- `build`: Build wireshark with the ccKex Plugin (in the docker container)
- `build_wireshark`: Build Wireshark with the ccKex Plugin (in the current context)
- `clean`: Clean all build files
- `help`: Show this help
- `init`: Initialize the cckex wireshark docker build container
- `init_wireshark`: Initialize the wireshark build environment with the ccKex Plugin (in the current context)
- `reset`: Reset the wireshark-plugin subfolder to it's initial state
- `run-shell`: Run the docker container and drop into a shell
