# AGENTS.md —— 仓库 AI 会话指引

> 若会话直接开在本仓库目录（而非上级工作区 `project_paau/`），本文件是你唯一保证能看到的指引。

## 立即要做的事

1. **阅读上级工作区的完整经验手册**：`../Tongsuo开发经验手册-供AI复用.md`（若文件不在，其要点已压缩在下方）。
2. 涉及标准文本（GB/T 34953.4）的任务另读 `../ZYHW实现问题记录.md`。

## 本仓库当前状态（2026-10-19）

- 分支 `feature/gbt34953-4-paea` 包含 ZYHW、YZW、SM9 BN256 pairing、有限域乘法 ElGamal 与统一 `EVP_PAEA_CTX`；低层入口仅供内部使用。接口说明 `README-PAEA.md`，来源与安全边界 `crypto/pairing/README.md`，标准问题在上级 `ZYHW实现问题记录.md`。
- 2026-10-19 已将原有 9 个提交 rebase 到官方 `origin/master`（`80cfbe3eb`），本地 `master` 同步到该基线。主线为 Tongsuo 8.5.0（OpenSSL 3.5.4 基线），不含 PAEA。

## 最关键的构建事实

- PAEA 模块**默认禁用**（Tongsuo 扩展模块惯例，同 paillier/zkp）：构建必须加 `enable-paea`，否则模块静默不参与编译且 make 不报错。
  `./Configure darwin64-arm64-cc --prefix=... no-shared enable-paea enable-pairing && make -j8`
- YZW 还需 `enable-pairing`。运行三组测试：`make test TESTS='test_pairing test_paea_evp test_paea_zh'`；切换配置后先完成 `make -j8 build_libs`，再单独构建测试目标，不能一起并行。
- OID 变更后需按 `Configurations/unix-Makefile.tmpl` 的 `generate_crypto_objects` 再生成 obj_dat.h/obj_mac.h（四条 perl 命令，见手册 §2.4）。

## 三个最致命的 API 陷阱（完整库见手册 §3）

1. BN 层（`BN_mod/BN_mod_add/BN_mul/BN_mod_inverse/BN_div`）的 BN_CTX **不允许 NULL**（内部直接 `BN_CTX_start`，段错误）；EC 层函数则普遍允许 NULL。
2. 每次调用生成新随机签名的输出函数（如 `paea_zyhw_server_auth_init`）**不可"先探长后写缓冲"两段式调用**——DER 签名长度逐次波动，探长结果对第二次调用无效，约 1/3 概率随机失败且无 ERR。
3. 候选拒绝/重试循环内的预期失败必须 `ERR_clear_error()`，防止错误队列残留淹没真实故障定位。

2026-10-19 API 评审修订：ZYHW 的 SM2 曲线仅允许 SM3（含公开参数导入检查）；移除复制敏感状态的 `EVP_PAEA_CTX_dup`，保留仅复制公开参数的 `EVP_PAEA_CTX_dup_public`。同一服务器上下文按完整鉴别串行复用，结束后 reset。当前三组 recipe 与两个独立 demo 已通过。

第二轮文档评审：旧 ZYHW/CRL/UID 公开声明与导出已移除，低层实现仅供 EVP 内部使用；四组 recipe 含新增 `test_paea_kat` 通过。KAT 数据和复现入口见 `test/recipes/30-test_paea_kat_data/vectors.json` 与 `test/paea_kat_test.c`（路径相对 Tongsuo）。
