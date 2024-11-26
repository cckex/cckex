# syntax=docker/dockerfile:latest

################################################################################
# kernel-kex
################################################################################
FROM ubuntu:22.04 as kernel-kex

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_API_LEVEL=31
ENV ANDROID_BUILD_TOOLS_LEVEL=32.0.0

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && apt install -y --no-install-recommends \
      vim \
      git \
      make \
      wget \
      python3-dev \
      python3-pip \
      python-is-python3 \
      unzip \
      openjdk-17-jre-headless \
      libpulse0 \
      libgl1 \
      libxcomposite1 \
      libxcursor1 \
      libxdamage1 \
      libxi6 \
      libxtst6 \
      lxterminal \
      tigervnc-standalone-server \
      build-essential \
      libssl-dev \
      libncurses5-dev \
      bzip2 \
      lib32z1 \
      bison \
      flex \
      libelf-dev \
      qttools5-dev-tools \
      qttools5-dev \
      meld \
      geany \
      libgtk-3-dev \
      libwebkit2gtk-4.0-dev \
      autogen \
      libgtk2.0-dev \
      libglade2-dev \
      openssh-client \
	  tshark \
	  software-properties-common \
	  gdb

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && apt install -y --no-install-recommends \
      python3-cachecontrol \
	  rsync

WORKDIR /opt/

# install Android Command Line Tools and accept all Licenses
ENV ANDROID_SDK_HOME=/root 
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
RUN wget 'https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip' -P /tmp
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools \
 && unzip -d ${ANDROID_SDK_ROOT}/cmdline-tools /tmp/commandlinetools-linux-9477386_latest.zip \
 && mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest \
 && yes Y | ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager --install "build-tools;${ANDROID_BUILD_TOOLS_LEVEL}" "platforms;android-${ANDROID_API_LEVEL}" "platform-tools" \
 && yes Y | ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager --licenses
ENV PATH="${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator"

# install Android Emulator
RUN sdkmanager emulator platform-tools "platforms;android-${ANDROID_API_LEVEL}" "system-images;android-${ANDROID_API_LEVEL};google_apis;x86_64"

# Clean up
RUN rm /tmp/commandlinetools-linux-9477386_latest.zip

# install Google repo to download kernel
RUN wget https://storage.googleapis.com/git-repo-downloads/repo -O /usr/bin/repo && chmod a+x /usr/bin/repo

WORKDIR /opt/

# download rootAVD and checkout good commit
RUN git clone https://github.com/newbit1/rootAVD.git

RUN cd /opt/rootAVD/ && git checkout 9ccee5c34678ffe810887a4aeff0288371d7436b

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install gpg-agent -y && add-apt-repository ppa:oisf/suricata-stable -y && apt update && apt install suricata jq -y --no-install-recommends curl tcpdump

ENV PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"
ENV MANPATH="/home/linuxbrew/.linuxbrew/share/man:$MANPATH"
ENV INFOPATH="/home/linuxbrew/.linuxbrew/share/info:$INFOPATH"
ENV JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64/"
ENV PATH=$PATH:$JAVA_HOME/bin

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | tac | tac | bash - && apt-get update && apt-get install -y nodejs
RUN npm install -g appium
RUN npm install wd 
RUN npm install appium-doctor -g 
RUN pip install Appium-Python-Client
RUN pip3 install frida frida-tools hexdump scapy watchdog click importlib-resources
