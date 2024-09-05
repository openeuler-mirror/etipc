Tipc仍按内核模块编译方式，将其代码放在product/8090/ssp/tipc目录，修改kernel/net目录Kconfig和Makefile文件

在 kernel/net/Kconfig中修改tipc/Kconfig所在目录，注意确认相对路径..的个数
source "../../../../product/8090/ssp/tipc/Kconfig"

在 kernel/net/Makefile中修改tipc/Makefile所在目录，注意..比上一个多一级
obj-$(CONFIG_TIPC)		+= ../../../../../product/8090/ssp/tipc/


# 运行时依赖条件，至少应有以下几个
# . env_8090.sh
# export KERNELDIR=$(V8_ROOT)/product/8090/bsp/kernel
# export KBUILD_OUTPUT=$(V8_ROOT)/obj/product/8090/bsp/mpu
# 其它地方执行即可
# make -C $(V8_ROOT)/product/8090/ssp/tipc



