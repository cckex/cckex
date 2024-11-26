![logo](logo_standalone.png)


# CCKex: High Bandwidth Covert Channels over Encrypted Network Traffic

The CCKex framework demonstrates how to leverage live cryptographic key extraction and data injection into encrypted and unencrypted network layers to achieve high bandwidth covert communication

Please refer to our [NordSec'24](https://nordsec2024.kau.se/) paper for more details: [CCKex: High Bandwidth Covert Channels over Encrypted Network Traffic](https://nordsec2024.kau.se/accepted-papers/)

## About 

Covert channels, such as the timing behavior of a process or the lowest order bit in a network protocol nonce, can be 
used to exchange information in a stealthy manner. Storage covert channels are a class of covert channels that modulate
ata onto unused or redundant protocol fields of existing network communication. Because of this restriction, but also
because of the ubiquity of encrypted communication, such channels usually suffer from severe bandwidth limitations. We
propose a novel storage-based covert channel that enables the transmission of data inside encrypted network traffic,
thus both drastically increasing bandwidth and stealth. In contrast to prior work, we assume the availability of
encryption keys on the sender side, a condition usually met by strong attackers applying key extraction from memory. In
this way, we are able to embed information into encrypted network traffic, experimentally increasing covert bandwidth
by a factor of 11. We demonstrate the practical feasibility of our approach targeting the Android app Signal on a
real-world smartphone.

## Requirement

We tested the CCKex on Ubuntu 22.04 and Manjaro 24.1.2 Xahea. You require `git` to download the source code.
Furthermore, the [docker engine](https://docs.docker.com/engine/install/ubuntu/) is required to build and run the demonstration. We tested `Docker version 27.2.1, build 9e34c9bb39`. Additionally, we are using the `docker compose` plugin (`Docker Compose version 2.29.5`) to create and run the container. 

## Demonstration

To demonstrate the capabilities of the CCKex Framework, first set up the [kernel-kexfil environment](kernel-kexfil/README.md) and the [Wireshark Plugin](wireshark-plugin/README.md). After the setup, use the `run-demo` target of the kernel-kexfil [Makefile](kernel-kexfil/Makefile) to generate a test capture to demonstrate the capabilities of the CCKex Framework. Either use the generated capture file or the provided [example file](kernel-kexfil/capture/frida/captures/example/_cap.pcap) to test the CCKex Wireshark Plugin.
