# LlmShark Roadmap


## 版本总览

| 版本 | 主要方向 | 代表提交 |
|------|----------|----------|
| Unreleased | fshark 解码模式探索、地图/交互辅助、仓库清理 | `cc81f61` `3027710` `0843578` |
| 1.1.0 | 批处理 CLI 工具链落地、配置收口、商店订阅防重复扣费、版本升级 | `87e414e` `83a2909` `e488dc9` `c114820` |
| 1.0.9 | 按授权动态限制 PCAP 大小、离线授权状态、移动端授权链路闭环 | `a2f2338` `1e4d0aa` `f631980` |
| 1.0.8 | 版本升级、英文知识库打包、解析/可视化增强 | `d0162fb` `7b3aba0` |
| ≤ 1.0.7（基线） | 早期功能与文档持续完善 | `0393f82` 等 |

---

## 下个 Release

- [ ] Support 2G/3G Legacy Network Signaling Analysis (#2)
- [ ] Support 5G SBA Interface Analysis (#3)

## Unreleased

### 新增特性
- 初始化 fshark 信令解码 CLI 项目  
  - `cc81f61` feat: 初始化fshark信令解码CLI项目
- parser / parser-batch：新增 fshark 解码模式与 `--fshark` 参数（探索性）  
  - `3027710` feat(parser, parser-batch): 新增fshark解码模式与--fshark命令行参数
- map：新增地图交互工具函数与 tom-select 样式（标注“未集成”）  
  - `9920744` feat(map): 未集成！新增地图交互工具函数和tom-select样式文件

### 问题修复 / 回滚
- 暂时禁用 fshark 模式以恢复正常诊断输出  
  - `0843578` fix(parser): 暂时禁用fshark模式恢复正常诊断输出

### 工程维护
- 停止跟踪 `.atomcode/graph.bin`  
  - `75aaaa1` 停止跟踪 .atomcode/graph.bin

---

## 1.1.0

### 新增特性（Batch CLI / 工具链）
- 新增批处理 CLI 与配套工具链  
  - `83a2909` feat: 新增批处理CLI及配套工具链
- batch-cli：支持多 LLM 配置并发资源池，并配套使用文档  
  - `e488dc9` feat(batch-cli): 增加多LLM配置并发执行能力并添加使用文档
- batch-cli：支持统一配置目录（`--config-dir`）、并改进基础解析器发现（独立目录部署链路更顺畅）  
  - `b8c47e8` feat(batch-cli): 支持统一配置目录并改进基础解析器发现

### 问题修复（商业化 / Store）
- store-module：拦截 Microsoft Store 跨订阅购买，避免用户重复扣费  
  - `c114820` fix(store-module): 拦截Microsoft Store跨订阅购买避免重复扣费

### 实验 / 工具
- 新增 DeepSeek 模型 tool 信号影响的 AB 测试工具与相关资源（验证性/证伪）  
  - `0b44922` 验证性/证伪 feat(ab_test): 新增DeepSeek模型tool信号影响的AB测试工具及相关资源

### 构建与文档
- 升级项目至 1.1.0 并更新桌面打包文档  
  - `87e414e` 构建: 升级项目至1.1.0版本并更新桌面打包文档
- 工程维护：停止跟踪本地工具配置文件（避免误入库）  
  - `b1554cf` chore: untrack .claude/settings.local.json

---

## 1.0.9

### 新增特性（授权与策略）
- 按许可证类型动态设置 PCAP 文件大小限制  
  - `a2f2338` (1.0.9) feat: 根据许可证类型动态设置PCAP文件大小限制
- store：增加离线授权状态支持  
  - `1e4d0aa` feat(store): 增加离线授权状态支持
- i18n：增加离线授权状态翻译并改进语言回退逻辑  
  - `f5f2e96` feat(i18n): 增加离线授权状态翻译并改进语言回退逻辑

### 新增特性（聊天与权限）
- chat：支持“无 PCAP 对话”但限制仅付费用户可用（权限门控）  
  - `26bbd70` feat(chat): 支持无PCAP对话功能仅限付费用户

### 新增特性（移动端授权闭环）
- 桌面端提供 QR 扫码用于授权移动端获取订阅信息/本地分析能力  
  - `f41c35e` feat(app): 提供QR扫码用于授权手机APP获取订阅信息使用本地分析功能；
- 移动端 Rust core：授权验证与策略计算；以及扫码授权链路与 FFI 桥接  
  - `72947c0` feat: 实现移动端Rust核心库的授权验证与策略计算  
  - `f631980` feat(mobile): 实现桌面到移动端的扫码授权链路与FFI桥接
- Android 宿主应用与安全链路：Keystore 管理 KEK、案例库加密与搜索解密管线等  
  - `0c198ab` feat(mobile): 添加 Android 宿主应用用于移动端授权验证  
  - `b703c10` feat(android): 新增案例库加密模块与Android宿主安全链路  
  - `5a4d388` feat(android): 集成 Android Keystore 管理 KEK 以增强密钥安全  
  - `642baf7` feat(mobile): 集成案例搜索与解密管线

---

## 1.0.8

### 新增特性
- 版本升级到 1.0.8，并加入英文知识库打包支持  
  - `d0162fb` (1.0.8) feat: 更新版本号并添加英文知识库打包支持
- parser：增强关键信令提取算法与 Mermaid 时序图生成  
  - `7b3aba0` feat(parser): 增强关键信令提取算法和Mermaid时序图生成
- kb：增强知识库解析与命中计数逻辑  
  - `c7d799e` feat(kb): 增强知识库解析和命中计数逻辑

### 问题修复
- 英文版案例库不可用时回落使用中文版案例库（避免英文库质量/可用性问题）  
  - `504e094` bugfix: 英文版案例库不可用，回落使用中文版案例库（英文版翻译质量太低，一直未启用）

---

## ≤ 1.0.7（基线）

- 以文档与体验完善为主的提交  
  - `0393f82` documentation  
  - `a4f6d89` documentation  
  - `60cca0d` documentation  
  - ...等
