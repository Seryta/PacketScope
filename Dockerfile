# Android build environment for PacketScope.
# 按项目规则不在宿主机直接构建，统一通过此镜像执行 gradle 任务。
#
# 用法：
#   docker build -t packetscope-build .
#   docker run --rm -v "$PWD":/work -w /work packetscope-build ./gradlew assembleDebug
#
# 缓存 gradle 依赖（推荐，避免每次重新下载）：
#   docker run --rm \
#     -v "$PWD":/work -w /work \
#     -v packetscope-gradle-cache:/root/.gradle \
#     packetscope-build ./gradlew assembleDebug

FROM mingc/android-build-box:latest

WORKDIR /work
