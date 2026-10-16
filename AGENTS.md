# AGENTS.md —— 仓库 AI 会话指引

> 若会话直接开在本仓库目录（而非上级工作区 `project_paau/`），本文件是你唯一保证能看到的指引。

## 立即要做的事

1. **阅读上级工作区的完整经验手册**：`../Tongsuo开发经验手册-供AI复用.md`（若文件不在，其要点已压缩在下方）。
2. 涉及标准文本（GB/T 34953.4）的任务另读 `../ZYHW实现问题记录.md`。

## 本仓库当前状态（2026-10-16）

- 分支 `feature/gbt34953-4-paea` 含 **ZYHW 匿名实体鉴别机制**实现（GB/T 34953.4 第 7.3 节）：模块 `crypto/paea/`，公开 API `include/openssl/paea.h`（`EVP_PAEA_*`），错误库 `ERR_LIB_PAEA`，OID `NID_zyhw_mechanism`（1.0.20009.4.2.2），测试 `test/paea_zyhw_test.c` + `test/recipes/30-test_paea_zh.t`（6/6 稳定）。
- 主线 master 分支为普通 Tongsuo（8.5.0-pre2，OpenSSL 3.5.4 基线），不含 PAEA。

## 最关键的构建事实

- PAEA 模块**默认禁用**（Tongsuo 扩展模块惯例，同 paillier/zkp）：构建必须加 `enable-paea`，否则模块静默不参与编译且 make 不报错。
  `./Configure darwin64-arm64-cc --prefix=... no-shared enable-paea && make -j8`
- 单独重编测试：`make test/paea_zyhw_test`；运行：`./test/paea_zyhw_test`
- OID 变更后需按 `Configurations/unix-Makefile.tmpl` 的 `generate_crypto_objects` 再生成 obj_dat.h/obj_mac.h（四条 perl 命令，见手册 §2.4）。

## 三个最致命的 API 陷阱（完整库见手册 §3）

1. BN 层（`BN_mod/BN_mod_add/BN_mul/BN_mod_inverse/BN_div`）的 BN_CTX **不允许 NULL**（内部直接 `BN_CTX_start`，段错误）；EC 层函数则普遍允许 NULL。
2. 每次调用生成新随机签名的输出函数（如 `EVP_PAEA_server_auth_init`）**不可"先探长后写缓冲"两段式调用**——DER 签名长度逐次波动，探长结果对第二次调用无效，约 1/3 概率随机失败且无 ERR。
3. 候选拒绝/重试循环内的预期失败必须 `ERR_clear_error()`，防止错误队列残留淹没真实故障定位。
