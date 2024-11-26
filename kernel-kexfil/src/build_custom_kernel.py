#!/usr/bin/env python3
import argparse
import os
import subprocess

def prepare_kernel(kernel_path):
    with open(kernel_path + "common-modules/virtual-device/build.config.virtual_device.x86_64", "a") as f:
        f.write("\nSKIP_CP_KERNEL_HDR=1\n")
        f.write('FILES="\narch/x86/boot/bzImage\nvmlinux\nSystem.map\n"\n')
        f.write('MAKE_GOALS="\nbzImage\nmodules\n"\n')

    with open(kernel_path + "common/arch/x86/configs/gki_defconfig", "a") as f:
        # this should already be defined
        #f.write("\nCONFIG_SECURITY_SELINUX=y\n")
        f.write("CONFIG_SECURITY_SELINUX_BOOTPARAM=y\n")
        f.write("CONFIG_SECURITY_SELINUX_DISABLE=y\n")
        #f.write("CONFIG_SECURITY_SELINUX_DEVELOP=y\n")

    # enable this if moduel loading is not already allowed
    #with open(kernel_path + "common/kernel/configs/android-base.config", "a") as f:
    #    f.write("\nCONFIG_MODULES=y\n")
    #    f.write("\nCONFIG_MODULE_UNLOAD=y\n")
    #    f.write("\nCONFIG_MODVERSIONS=y\n")

    # add custom kernel module
    with open(kernel_path + "common-modules/virtual-device/Kbuild", "a") as f:
        f.write("\nobj-m += custom_kernel_module/\n")

def setup_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel_dir", help="absolut path to root directory for linux source code")
        
    return parser

def main():
    arg_parser = setup_args()
    args = arg_parser.parse_args()

    kernel_path = args.kernel_dir
    
    prepare_kernel(kernel_path)
    print("Kernel prepared!\n")
    
    compile_env = os.environ.copy()
    compile_env["BUILD_CONFIG"] = "/common-modules/virtual-device/build.config.virtual_device.x86_64"
    #compile_env["BUILD_CONFIG"] = "common/build.config.gki.x86_64"
    cmd_line = kernel_path + "/build/build.sh -j$(nproc)"
    # build kernel
    p = subprocess.Popen(cmd_line, cwd=kernel_path, env=compile_env, shell=True)
    
    try:
        p.wait()
    except KeyboardInterrupt:
        p.terminate()

    

if __name__ == '__main__':
    main()

