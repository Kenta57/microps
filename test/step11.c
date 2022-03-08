#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    // あらかじめ設定されたシグナルが飛んできたら, カーネルが登録されたハンドラを呼び出す. (元のプロセスに割り込む形で実行され, 実行後は元に戻る)
    signal(SIGINT, on_signal); // ctrl + c のときに終了のフラグのterminateを変更するだけのハンドラの登録
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }

    return 0;
}

static void
cleanup(void)
{
    net_shutdown();
}

int
main(int argc, char *argv[])
{
    ip_addr_t src, dst;
    uint16_t id, seq = 0;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src;
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        // test_dataはicmp, ipヘッダがついた状態のもの, それらのデータは自分でつけるため, *dataではtest_dataの先頭からヘッダー分だけ進めておく, またlenも同様にヘッダー分だけ削る
        // test_data + offsetは　uint8_tなのでアドレスの演算は1byteずつ進む
        if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
            errorf("icmp_output() failure");
            break;
        }
        sleep(1);
    }
    cleanup();
    return 0;
}
