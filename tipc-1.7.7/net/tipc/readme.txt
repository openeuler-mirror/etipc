Tipc�԰��ں�ģ����뷽ʽ������������product/8090/ssp/tipcĿ¼���޸�kernel/netĿ¼Kconfig��Makefile�ļ�

�� kernel/net/Kconfig���޸�tipc/Kconfig����Ŀ¼��ע��ȷ�����·��..�ĸ���
source "../../../../product/8090/ssp/tipc/Kconfig"

�� kernel/net/Makefile���޸�tipc/Makefile����Ŀ¼��ע��..����һ����һ��
obj-$(CONFIG_TIPC)		+= ../../../../../product/8090/ssp/tipc/


# ����ʱ��������������Ӧ�����¼���
# . env_8090.sh
# export KERNELDIR=$(V8_ROOT)/product/8090/bsp/kernel
# export KBUILD_OUTPUT=$(V8_ROOT)/obj/product/8090/bsp/mpu
# �����ط�ִ�м���
# make -C $(V8_ROOT)/product/8090/ssp/tipc



