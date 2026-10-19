# PAEA 试点接口（2026-10-19）

实现 2026-06-12 征求意见稿 7.3 ZYHW 和 7.2 YZW，统一入口为
`<openssl/paea.h>` 中的 `EVP_PAEA_*`。这是 libcrypto 的协议上下文接口，
不把多轮协议包装成 `EVP_PKEY_sign()`，也未增加 provider operation。
原 `paea_zyhw_*`、CRL 及 UID 辅助入口已移入私有头并停止导出；应用统一使用 EVP API。YZW 使用 `<openssl/pairing.h>` 的 SM9 BN256
双线性对与新增的内部有限域乘法 ElGamal；原 EC_ELGAMAL API 保留。

## 构建与测试

```
./Configure darwin64-arm64-cc no-shared enable-paea enable-pairing
make -j8
make test TESTS='test_pairing test_paea_evp test_paea_zh test_paea_kat'
make -C examples paea_evp
./examples/paea_evp YZW
./examples/paea_evp ZYHW
```

其他平台使用对应 Configure target。`enable-paea no-pairing` 仅提供 ZYHW；
`enable-pairing no-paea` 可独立使用 pairing。两个扩展均默认禁用，依赖 EC。

## 两个独立的 C demo

- [`examples/paea_zyhw_demo.c`](examples/paea_zyhw_demo.c)：SM2/SM3，
  服务器发 M1 → 客户端验证并发 M2 → 服务器验证完成。
- [`examples/paea_yzw_demo.c`](examples/paea_yzw_demo.c)：SM9-BN256/SM3，
  客户端发 M1 → 服务器发 M2 → 客户端验证并发 M3 → 服务器验证完成；
  双线性对与有限域乘法 ElGamal 由库内部处理。

两个源文件均自包含，使用公开的 `EVP_PAEA_*` API，带有 `main()`，不依赖
测试框架或内部头文件。先阅读 `main()` 中的建立和注册，再看 `authenticate()`
中的逐消息调用。服务器始终不接收口令；客户端通过公开参数导入建立独立上下文，
在本地以口令包裹注册凭证。YZW 必须在颁发凭证后导出公开参数，以包含最新累加器。

在仓库根目录运行：

```sh
./Configure darwin64-arm64-cc no-shared enable-paea enable-pairing
make -j8 build_libs
make -C examples paea_demos
./examples/paea_zyhw_demo
./examples/paea_yzw_demo
```

也可用 `make -C examples test_paea_demos` 一次运行两个示例。只测试 ZYHW 时可
使用 `enable-paea no-pairing` 构建库，再 `make -C examples paea_zyhw_demo`。
如需直接编译其中一个：

```sh
cc -std=c99 -Wall -Wextra -Iinclude examples/paea_yzw_demo.c libcrypto.a \
   -lpthread -o examples/paea_yzw_demo
```

每个 demo 都验证六个场景：正确口令、错误口令、篡改报文、失败后重新鉴别、
已撤销用户刷新撤销辅助值失败、已撤销用户持旧凭证鉴别失败。成功场景用
`CRYPTO_memcmp()` 比较双方 32 字节会话密钥，拒绝场景额外检查服务器取不到密钥。
ZYHW 篡改客户端证明，YZW 篡改服务器 MAC；每次尝试前重置双方会话。
当前 ZYHW 验证器对证明不匹配返回 `PAEA_R_BAD_MESSAGE`，YZW 返回
`PAEA_R_VERIFY_FAILED`，demo 按实际接口检查预期错误，初始化失败不会视作测试通过。

程序打印消息方向、字节数和 `[PASS]`，不输出口令、凭证或密钥内容；所有检查通过
返回 0，异常返回非零。测试口令是代码内固定样例，报文只在内存中传递。
示例不实现网络、可信参数分发和对端显式密钥确认；客户端能取得本地密钥并不说明
服务器已经接受，示例只在服务器验证完成后比较双方密钥。

## 生命周期与所有权

1. `EVP_PAEA_CTX_new_ex(libctx, "ZYHW" 或 "YZW", propq)` 创建空上下文。
   `libctx` 为借用引用，须比上下文长寿；`propq` 被复制。选择不区分大小写。
2. 在 setup/import 之前以 `EVP_PAEA_CTX_set_params()` 设置 OSSL_PARAM：
   `group`、`digest` 为 UTF8_STRING，`revocation` 为 INTEGER 0/1。
   ZYHW 默认 SM2/SM3，SM2 曲线仅允许 SM3；其他曲线可使用 P-256/SHA256 等配置。
   setup 与公开参数导入都会检查 SM2/SM3 约束；YZW 当前仅接受 SM9-BN256/SM3。
3. `EVP_PAEA_setup()` 生成一个服务器上下文。已建立的上下文不能重复 setup。
   参数/长期密钥轮换需创建新服务器，并重新注册用户。
4. 服务器以 `EVP_PAEA_issue_credential(uid)` 返回秘密注册数据。
   **先注册，再复制服务器公开参数**（YZW 注册会改变累加器）。
   客户端经 `CTX_dup_public()`，或在空上下文上 `import_public()`，取得可信公开参数；
   随后 `store_credential(uid, password, issued)` 在本地包裹凭证。
   库不需要把口令交给服务器。注册数据用后立即 `OPENSSL_clear_free()`。
5. 用 `export_credential()` 保存已包裹的凭证；恢复时先导入相应公开参数，再
   `import_credential()`。错误口令在协议中判定，导入接口不验证口令。
   公开参数与凭证是版本 1 的私有编码，尚非标准互操作格式。
6. 每个上下文最多一轮在途鉴别。`CTX_dup_public()` 仅复制公开参数，
   不复制任何长期秘密、用户凭证或会话密钥；不提供服务器秘密状态复制接口。
   同一服务器上下文依次处理各次鉴别，每次结束后 reset，再使用原长期密钥。
7. `EVP_PAEA_CTX_free()` 释放上下文；所有输出缓冲由库一次分配，调用者释放。
   出错返回 0/NULL；常规整数接口成功返回 1，`get0_name()` 返回借用的机制名。
   必填指针必须有效，零长度输入可以使用 NULL。随机报文不使用两次探长调用。

所有输出 `unsigned char **out` 的调用将输出初始化为 NULL/0。
`get_session_key()` 例外：`out == NULL` 查询已完成会话的固定密钥长度；否则
调用前 `*outlen` 是容量，不足时返回 0 并写入所需长度。

## 鉴别调用顺序

YZW 为：客户端 `auth_init(password)` 产生 M1；服务器 `auth_step(M1)` 产生 M2；
客户端 `auth_step(M2)` 产生 M3；服务器 `auth_step(M3)` 验证并返回空输出。

ZYHW 为：服务器 `auth_init(NULL,0)` 产生 M1；客户端
`auth_step(password,M1)` 产生 M2；服务器 `auth_step(M2)` 验证并返回空输出。
这是草案的鉴别交互部分；注册独立进行。

只有本地完成证明/验证后才能 `get_session_key()`。客户端完成证明不能确认
服务器已经接受，错误口令下也可能先得到一个双方不一致的本地密钥。
应用需要确认对端接受时，应使用该密钥进行后续显式确认。
鉴别失败消耗当前会话，重复提交不会继续使用旧随机数；成功也立即销毁临时秘密。
`auth_reset()` 清除会话与密钥，为全新鉴别做准备。参数和凭证不会因此变化。

## 撤销与并发

库没有公开状态查询接口。应用根据调用结果维护进度：服务器 setup 成功、
客户端 import_public 及 store/import_credential 成功后，且没有进行中的鉴别时，
可执行管理操作；参加过鉴别的上下文先 auth_reset。
服务器在上述空闲状态调用 `revoke(uid)`。客户端在空闲状态通过
`refresh(client, trusted_source)` 更新撤销辅助值、累加器和历史记录。
source 可是服务器或由可信公开参数导入的上下文，不能来自其他系统。
刷新检查已有历史是 source 的前缀，拒绝回滚；对自己已被撤销的客户端返回失败。
失败不会发布部分更新。YZW 新注册也改变累加器，旧用户同样需要刷新。
YZW 启用撤销时记录 uid 的 SM3 与 k 的对应关系，用于拒绝重复注册并定位撤销对象；
这些对应关系不会公开导出。YZW 客户端 store 不使用 uid 参与凭证计算，
也不检查其与注册数据的绑定；注册渠道负责确认用户身份并正确交付注册数据。
两种机制的公开参数都携带撤销数据：ZYHW 启用撤销时包含累加器与撤销列表，
YZW 始终编码累加器，启用撤销时还包含添加/删除记录。

应用应保留唯一的注册/撤销权威。同一服务器上下文依次完成各次鉴别，
客户端通过 refresh 更新公开参数和撤销辅助值。上下文不允许并发修改；库不负责锁、
网络传输、可信目录、磁盘反回滚或多服务器同步。

公开参数只包含验证所需数据，不含 x、chi、ElGamal 私钥或 uid 映射。
此版本提供用户凭证持久化；尚无服务器秘密复制或导入导出接口。
长时间运行和重启恢复所需的密钥存储接口属于后续工程范围。

## YZW 试点配置与边界

- 配对：SM9 BN256，G1/G2/GT 阶相同，R-ate pairing，参数及来源见
  [配对后端说明](crypto/pairing/README.md)。
- 同态加密：RFC 3526 3072-bit MODP 素数 P，生成元 4，阶 (P-1)/2；
  明文为非零 Fp 元素。P 大于 q²；r*s 先作为整数解密，再 mod q 用于配对指数。
  不使用加法同态的 EC_ELGAMAL，也不对大标量进行离散对数恢复。
- 口令包裹：SM4-CTR，随机 16 字节 IV，密钥取 SM3(password) 的前 16 字节；
  m' 和 NU 为 64 字节，MAC 为 HMAC-SM3，SK 为 SM3 输出。
  按草案仅加密 m'，不加密 M、k、wit，也不附加可验证口令的标签。
- 每字段 `u32be(length)||value`，标量 32 字节、G1 65、G2 129、GT 384、
  ElGamal 密文 768 字节。哈希/MAC 按固定字段值串接，不加入字段长度。
  撤销承诺被追加到服务器 MAC 输入，作为本试点的明确扩展。
- UID 最多 512 字节；任一输入 blob 最多 1 MiB；YZW 累加器历史最多 4096 个
  添加/删除事件。不能在不重新颁发撤销辅助值的情况下任意截断历史。

**安全与符合性尚未完结**：pairing 后端未进行常数时间改造；草案的 ElGamal
完整消息域与素数阶掩码子群不匹配，会暴露明文的二次剩余类别，0 则直接暴露。
本实现拒绝 0，但没有解决一般的类别泄露，不能称为任意位串 IND-CPA 安全加密。
SM4-CTR 是否满足草案所称“序列密码算法”、最终曲线安全等级、私有编码、公式勘误
和消息绑定扩展都需标准组确认。功能测试不等于安全证明或标准符合性认证。
详细问题及依据记在工作区 `ZYHW实现问题记录.md`。

## 已知答案测试

`make test TESTS=test_paea_kat` 只读 `test/recipes/30-test_paea_kat_data/` 固化答案，逐字节比较两机制在撤销关闭/开启时的参数、凭证、消息与密钥。完整输入、输出十六进制和随机流约定见该目录 `vectors.json`，复现程序为 `test/paea_kat_test.c`。固定随机数仅限测试，属于本实现的回归 KAT，不是标准发布的向量或独立实现互测认证。
