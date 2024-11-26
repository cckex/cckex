FROM ubuntu:22.04 as wireshark_build_container 

################################
##  -=# INSTALL PACKAGES #=-  ##
################################

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install Packages and Programs
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
	apt update && apt install -y --no-install-recommends \
		automake \
		autoconf \
		bison \
		build-essential \
		bzip2 \
		ccache \
		cmake \
		curl \
		doxygen \
		flex \
		freeglut3-dev \
		g++ \
		gcc \
		git \
		gpg-agent \
		libbrotli-dev \
		libc-ares-dev \
		libcap-dev \
		libgcrypt-dev \
		libgtk2.0-dev \
		libglib2.0-dev \
		libgnutls28-dev \
		libkrb5-dev \
		liblz4-dev \
		libmaxminddb-dev \
		libminizip-dev \
		libnghttp2-dev \
		libnl-3-dev \
		libnl-cli-3-dev \
		libopencore-amrnb-dev \
		libopus-dev \
		libparse-yapp-perl \
		libpcap-dev \
		libpcre2-dev \
		libqt5svg5-dev \
		libqt6core5compat6-dev \
		libqt6svg6-dev \
		libsbc-dev \
		libspeexdsp-dev \
		libssh-gcrypt-dev \
		libsmi2-dev \
		libsnappy-dev \
		libspandsp-dev \
		libsystemd-dev \
		libvulkan-dev \
		libxkbcommon-dev \
		libxml2-dev \
		libzstd-dev \
		lua5.4 \
		make \
		ninja-build \
		perl \
		python3 \
		qt5-qmake \
		qtbase5-dev \
		qtbase5-dev-tools \
		qtchooser \
		qtmultimedia5-dev \
		qttools5-dev \
		qttools5-dev-tools \
		qt6-base-dev \
		qt6-multimedia-dev \
		qt6-tools-dev \
		qt6-tools-dev-tools \
		qt6-l10n-tools \
		software-properties-common \
		unzip \
		vim \
		wget \
		xsltproc
