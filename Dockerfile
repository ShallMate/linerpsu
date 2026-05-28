# syntax=docker/dockerfile:1.7

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG BAZEL_VERSION=6.5.0
ARG YACL_REPO=https://github.com/ShallMate/yacl.git
ARG YACL_REF=f978244b8cd00976af840ae3d47116f6f7ec017e
ARG SECURE_JOIN_REPO=https://github.com/ladnir/secure-join.git
ARG SECURE_JOIN_REF=377ca63b9d8f4f6aede0d3a2e3d9078973a3ee10
ARG LIBOTE_REPO=https://github.com/osu-crypto/libOTe.git
ARG LIBOTE_REF=a403ec37c6a32148648b7d8fd66dc35318d9f99d
ARG LINERPSU_DEPS=/opt/linerpsu-deps

SHELL ["/bin/bash", "-lc"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    && add-apt-repository universe \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    libboost-all-dev \
    libgflags-dev \
    libgmp-dev \
    libgoogle-glog-dev \
    libntl-dev \
    libsodium-dev \
    libssl-dev \
    libtool \
    libunwind-dev \
    nasm \
    ninja-build \
    openjdk-17-jdk-headless \
    perl \
    pkg-config \
    python3 \
    unzip \
    wget \
    zip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/bazel \
      "https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-x86_64" \
    && chmod +x /usr/local/bin/bazel

ENV LINERPSU_DEPS=${LINERPSU_DEPS}
ENV SECURE_JOIN_ROOT=${LINERPSU_DEPS}/secure-join
ENV LIBOTE_ROOT=${LINERPSU_DEPS}/libOTe
ENV LIBOTE_PIC_ROOT=${LINERPSU_DEPS}/libOTe-pic

WORKDIR /opt

RUN git clone "${SECURE_JOIN_REPO}" "${SECURE_JOIN_ROOT}" \
    && git -C "${SECURE_JOIN_ROOT}" checkout "${SECURE_JOIN_REF}" \
    && cmake -S "${SECURE_JOIN_ROOT}" -B "${SECURE_JOIN_ROOT}/out/build/linux" \
         -DCMAKE_BUILD_TYPE=Release \
         -DFETCH_AUTO=ON \
         -DSUDO_FETCH=OFF \
         -DENABLE_CIRCUITS=ON \
         -DENABLE_MRR=ON \
         -DENABLE_IKNP=ON \
         -DENABLE_SOFTSPOKEN_OT=ON \
         -DENABLE_SILENTOT=ON \
         -DENABLE_SILENT_VOLE=ON \
         -DENABLE_BITPOLYMUL=ON \
         -DSODIUM_MONTGOMERY=OFF \
         -DSECUREJOIN_ENABLE_BOOST=OFF \
    && cmake --build "${SECURE_JOIN_ROOT}/out/build/linux" --parallel "$(nproc)"

RUN git clone "${LIBOTE_REPO}" "${LIBOTE_ROOT}" \
    && git -C "${LIBOTE_ROOT}" checkout "${LIBOTE_REF}" \
    && git -C "${LIBOTE_ROOT}" submodule update --init --recursive \
    && cmake -S "${LIBOTE_ROOT}" -B "${LIBOTE_ROOT}/out/build/linux" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX=/usr/local \
         -DFETCH_AUTO=ON \
         -DFETCH_SODIUM=ON \
         -DFETCH_RELIC=ON \
         -DFETCH_BITPOLYMUL=ON \
         -DENABLE_BITPOLYMUL=ON \
         -DENABLE_RELIC=ON \
         -DENABLE_MRR=ON \
         -DENABLE_MRR_TWIST=ON \
         -DENABLE_SIMPLESTOT=ON \
         -DENABLE_SIMPLESTOT_ASM=ON \
         -DENABLE_MR_KYBER=ON \
         -DENABLE_IKNP=ON \
         -DENABLE_SOFTSPOKEN_OT=ON \
         -DENABLE_SILENTOT=ON \
         -DENABLE_SILENT_VOLE=ON \
         -DENABLE_BOOST=ON \
         -DENABLE_SODIUM=ON \
         -DLIBOTE_STD_VER=20 \
    && cmake --build "${LIBOTE_ROOT}/out/build/linux" --parallel "$(nproc)" \
    && cmake --install "${LIBOTE_ROOT}/out/build/linux" \
    && ldconfig

RUN install -d "${LIBOTE_PIC_ROOT}/deps" \
    && cmake -S "${LIBOTE_ROOT}" -B "${LIBOTE_PIC_ROOT}/rebuild" \
         -DCMAKE_BUILD_TYPE=Release \
         -DENABLE_PIC=ON \
         -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
         -DCMAKE_INSTALL_PREFIX="${LIBOTE_PIC_ROOT}/install" \
         -DOC_THIRDPARTY_HINT="${LIBOTE_PIC_ROOT}/install" \
         -DOC_THIRDPARTY_INSTALL_PREFIX="${LIBOTE_PIC_ROOT}/install" \
         -DOC_THIRDPARTY_CLONE_DIR="${LIBOTE_PIC_ROOT}/deps" \
         -DFETCH_AUTO=ON \
         -DFETCH_SODIUM=ON \
         -DENABLE_MRR=ON \
         -DENABLE_MRR_TWIST=ON \
         -DENABLE_SIMPLESTOT=ON \
         -DENABLE_IKNP=ON \
         -DENABLE_SOFTSPOKEN_OT=ON \
         -DENABLE_SILENTOT=ON \
         -DENABLE_SILENT_VOLE=ON \
         -DENABLE_BOOST=ON \
         -DENABLE_SODIUM=ON \
         -DLIBOTE_STD_VER=20 \
    && cmake --build "${LIBOTE_PIC_ROOT}/rebuild" --parallel "$(nproc)" \
    && cmake --install "${LIBOTE_PIC_ROOT}/rebuild"

WORKDIR /workspace

RUN git clone "${YACL_REPO}" /workspace/yacl \
    && git -C /workspace/yacl checkout "${YACL_REF}" \
    && rm -rf /workspace/yacl/examples/linerpsu

COPY . /workspace/yacl/examples/linerpsu

WORKDIR /workspace/yacl

RUN python3 examples/linerpsu/tools/patch_workspace.py

RUN bazel build \
    --experimental_cc_shared_library \
    --copt=-Wno-error \
    --cxxopt=-std=c++17 \
    --host_cxxopt=-std=c++17 \
    --jobs="$(nproc)" \
    //examples/linerpsu:ourpsu

ENV LINERPSU_LOGN=20

CMD ["bazel-bin/examples/linerpsu/ourpsu"]
