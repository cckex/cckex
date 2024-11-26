# CCKex: kernel-kex

[[_TOC_]]

# About kernel-kex

The goal of kernel-kex is to implement a forensic tool capable of exfiltrating cryptographic keys from an Android device at runtime. Currently, this functionality is provided by the [custom Loadable Kernel Module](kernel-kexfil/src/custom_kernel_module) and the bash/frida scripts found in the `capture/` folder.

# Setup

Currently, two modes of operation are possible to test the CCKex Framework. The first is via an Android Virtual Device through the Android Emulator. The second is via a real Google Pixel device.
Both setups use Docker and Docker Compose to some extent. Thus, first [setup Docker on your device](https://docs.docker.com/engine/install/).

## Virtual Device

The kernel-kexfil container is separated from the host network into the `172.17.0.0/16` subnet. Usually, `172.17.0.2` is assigned as the container address. To view the Emulator when it is running, a vnc server in the container is exposed on port 5902. To view it use a vnc client, e.g. `vncviewer 172.17.0.2:5902`.

### Initial Setup

Run the `make init` target to set up a newly cloned (or reset) repository. This target will invoke the `make build` target (setting up the docker container) and the `make run-setup` target (setting up the kernel build system in the container and building it for the first time). At the end of this target, the Emulator is invoked and a container shell is available. Use this opportunity to set up / register the Signal App. Alternatively, the Signal can be set up later by invoking the Emulator, e.g., via the `make run-recompile` target or by running `make run-shell` and executing the `/src/create_and_run_emulator.sh` script manually in the container shell.

After completing this initial setup, move on to the [Usage](#usage) section.

### Troubleshooting

If you get an error that your Signal Version is too old, then replace the APK file in the [share](kernel-kexfil/share) directory and rerun the `make init` target.

## Real Hardware

After running `make init,` run the `make run-setup-hw` target to download and set up the hardware kernel. This step should also patch all necessary files in the kernel source to build the CCKex module. If the build fails or the CCKex module is not build correctly, see the following Troubleshooting section. Run the `make run-recompile-hw` target to trigger a kernel rebuild (Use this target if you have already completed the setup to rebuild the CCKex module). The CCKex module can be deployed by either rooting the hardware device and inserting the module with `insmod` (use this for unstable builds and rapid deployments - this is the current configuration) or by changing the kernel build files to include the CCKex module as a driver (use this for stable builds and permanent deployment). For the second option, follow the Google Pixel Kernel Build Guide [1] to learn how to flash the kernel to the device. If the `run-setup-hw` target fails during the kernel build, use the `run-recompile-hw` to trigger another kernel build after fixing the issue.

[1] https://source.android.com/docs/setup/build/building-pixel-kernels?hl=de

### Troubleshooting

After a successful build, the module LKM `cc_kex.ko` should be included in the build artifacts and the `dist` folder (which also includes the build kernel image). If this is not the case, then this could indicate that the `run-setup-how` target failed to set up the kernel build files correctly. To include the custom kernel module in the Android kernel build, the following changes must be made:
- `pixel_kernel/aosp/drivers/Makefile`: Add the line `obj-m += cc_kex/` to the bottom of the file.
- `pixel_kernel/aosp/drivers/Kconfig`: Add the line `"drivers/cc_kex/Kconfig"` before the last line (which should contain `endmenu` - add the CCKex Kconfig line in front of this one).
- `pixel_kernel/private/gs-google/BUILD.bazel`: Add the line `"cc_kex.ko"` in the `module_outs` list as a new line / entry.
- `pixel_kernel/asop/android/gki_aarch64_modules`: Add the line `drivers/cc_kex/cc_kex.ko` to this file. This file should be empty.
- Create a symlink from the LKM sources to the kernel drivers directory: `ln -s <lkm_source_dir> pixel_kernel/aosp/drivers/cc_kex`.

After verifying the changes above, if the module `cc_kex.ko` still is not included in the dist folder, try searching for it in all build artefacts (the `pixel_kernel/outs` folder): `find . -name cc_kex.ko`. If `cc_kex.ko` is found in the build artefacts, it should be usable. However, this still indicates a misconfigured build system.

The hardware build targets are not as streamlined as the virtualized build targets. 

# Usage

## Demonstration

Use the `make run-demo` target to start a _manual_ demonstration of the capabilities of the CCKex Framework:

- Invoke the `make run-demo` target to set up and start the manual test
- Start the VNC viewer to view the Emulator
- Wait for the Emulator to fully boot (notice that the Emulator will reboot once)
- Hit any key in the container shell to start the manual test (this will also start Signal)
- Write some messages to a test contact to enable CCKex to inject data
    - To monitor the status of the exfiltrated payload data in the LKM, open another container shell and use `adb shell dmesg -w` to view the ongoing injection
    - A traffic dump of the phone is provided after the test - alternatively, the traffic can also be directly captured by a local Wireshark instance via the docker network interface
- To end the test, close Signal via the Square Button in the right, bottom corner
- A traffic dump + files related to the test will be saved in the [eval directory](kernel-kexfil/capture/frida/captures/eval/current) - please refer to [this README](kernel-kexfil/capture/frida/captures/README.md) to get a detailed description of the test artifacts

### Recompilation

After you make changes to the code, use the `make run-recompile` target to rebuild the kernel or custom kernel module.

## Running custom Tests

Use the `make run-recompile` target to rebuild the kernel/custom LKM and run the Emulator. After that, the scripts in the [captures directory](kernel-kexfil/capture/frida/captures) can be used to run manual or automatic tests. To learn more, please refer to [this README](kernel-kexfil/capture/frida/captures/README.md).
