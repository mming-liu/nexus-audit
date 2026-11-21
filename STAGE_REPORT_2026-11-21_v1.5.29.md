# STAGE REPORT · v1.5.29（M463–M466：compose 端口映射死代码 / 弱哈希非安全用途 / akb 3 条焦点白盒）

> 日期：2026-11-21 ｜ 基线：v1.5.28（`52bb1f7`，巡猎产物 `8b547ff`）
> 主题：修复 `_PORT_MAP_RE` 双冒号死代码与 `eval/` 目录误判（解除 akb 18 条
> 记录的 `LOCAL_LOOPBACK_ONLY` 误压）；豁免 `# nosec B324` /
> `usedforsecurity=False` 与缓存键/ETag/指纹类弱哈希（fojin A 2 → 0）；
> akb 3 条焦点白盒精核；新增门禁 `[352]`。
> 结论：smoke **1,825** 项断言 PASS / triage **16/16** / doctor PASS；
> 离线复扫 fojin hash 2 → 0、akb `LOCAL_LOOPBACK_ONLY` 18 → 0。

## 〇、背景（11-21 09:00 巡猎）

- 巡猎耗时 6.5 分钟（11-19 / 11-20 分别为 68.5 / 40.5 分钟），0 失败；
- 板块 A 2 条全部是 fojin `hash`（`get_kg_timeline` / `get_kg_lineage_arcs`）；
- 板块 B 中 akb 有 18 条被 `LOCAL_LOOPBACK_ONLY` 压掉，但拦截理由指向的是
  `eval/longmemeval/docker-compose.yaml`，与记录本身（含
  `docker-compose.keycloak.yaml` 凭据文件）不是同一个部署面 —— 两条独立
  规则缺陷由此暴露。

## 一、M463：`_PORT_MAP_RE` 死代码 + `eval/` 目录 + 云原生清单 + `hardcoded_secret`

### 1. `_PORT_MAP_RE` 必须允许**省略主机 IP**（`core/context/wild_noise.py`）

```python
# 旧：写死三段式 host:port:port
_PORT_MAP_RE = re.compile(
    r"^\s*-\s*[\"']?([0-9A-Za-z_.:\[\]-]*?):(\d+):(\d+)[\"']?\s*$", re.M)

# 新：主机 IP 前缀可选，支持 /tcp /udp 与行尾注释
_PORT_MAP_RE = re.compile(
    r"^\s*-\s*[\"']?(?:([0-9A-Za-z_.:\[\]-]+):)?(\d+):(\d+)"
    r"(?:/(?:tcp|udp))?[\"']?\s*(?:#.*)?$",
    re.M)
```

旧正则对标准公网映射 `- "8000:8000"`（只有两段）**永远不匹配**，于是
`elif not host_ip: public_hit = ...` 是 100% 死代码。akb 主
`docker-compose.yaml` 发布 `9000:9000` / `9001:9001`，被判整仓单机；本次
在 `_repo_loopback_only()` 中把 `None` / `""` / `"0.0.0.0"` / `"::"`
统一视为公网映射：

```python
elif host_ip in (None, "", "0.0.0.0", "::"):
    public_hit = f"{rel} 端口映射 {m.group(2)}:{m.group(3)}"
    break
```

### 2. `_SCAN_SKIP_DIRS` 扩到评测/脚本目录

新增 `eval` / `evals` / `benchmark` / `benchmarks` / `scripts` / `hack` /
`ci`。评测环境的 compose 只服务跑分，不是生产部署面；旧逻辑把它当成
主配置，才出现"eval 里的 `127.0.0.1` 压掉整个产品仓"。

### 3. 云原生部署清单优先

新增 `_has_orchestration_manifests()`：仓内存在 `deploy/k8s`、`k8s`、
`deploy/helm`、`helm`、`deploy/charts`、`charts` 等目录且至少有一个
`.yaml` / `.yml` 时，直接判"非整仓单机"。akb 同时有 `deploy/k8s` 与
`deploy/helm`，这是比本地 compose 更强的部署证据。

### 4. `hardcoded_secret` 不继承 `LOCAL_LOOPBACK_ONLY`

```python
_repo_loop, _repo_ev = _repo_loopback_only(repo_root)
if _repo_loop and str(record.get("category") or "") != "hardcoded_secret":
    return {"blocked": True, "code": LOCAL_LOOPBACK_ONLY, ...}
```

凭据一旦提交进仓库，任何能读到仓库的人都拿到了它，"本机服务"不是它的
信任边界；11-21 的 akb 实测里，压掉 `[secret-file] docker-compose.keycloak.yaml`
的证据文件是 `eval/longmemeval/docker-compose.yaml` —— 理由和对象错配。

## 二、M464：弱哈希的非密码学用途（`core/agents/rule_detectors.py`）

`hashlib.md5/sha1` 不只用于口令与签名：缓存键、ETag/条件请求校验、内容
指纹、去重摘要也用。新增 `_weak_hash_is_non_security(region, body)`，只对
Python 的 `hashlib` 弱哈希调用生效，两层判据：

1. **显式声明**：入口段里每一处弱哈希调用所在行都带 `# nosec`
   （bandit B324），或调用参数带 `usedforsecurity=False`；
2. **上下文推断**：入口方法体里所有弱哈希调用都落在
   `cache / etag / W/" / fingerprint / content_hash / checksum / dedup`
   语境，且整段不含 `password / passwd / pwd / token / secret / sign /
   hmac / auth`。

任一条不满足就退回原判定（Java 的 `MessageDigest` / `DigestUtils` 路径
完全不变）。fojin 实测：

```python
cache_key = f"kg:timeline:{hashlib.sha1(key_payload.encode()).hexdigest()}"  # nosec B324
cache_key = f"kg:lineage:gz:{hashlib.sha1(key_payload.encode()).hexdigest()}"  # nosec B324
h = hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]
```

### 回归面（有界扫描）

对 `reference_repos/` 9 个地板靶场 + fojin + akb 共 **2,159** 个 `.py`
做静态扫描：含弱哈希的文件 12 个，被新判据豁免的只有 **4 个**，全部是
fojin 的缓存键 / 内容指纹（`knowledge_graph.py` / `embedding.py` /
`feed_service.py` / `stats_service.py`），靶场语料零豁免。负向对照：

| 样本 | 结果 |
|---|---|
| `hashlib.md5(password.encode())` | `True`（仍判弱哈希） |
| `hashlib.sha1(secret + data)` | `True` |
| `hashlib.sha1(api_token.encode())` | `True` |
| Java `MessageDigest.getInstance("MD5")` + `password` | `True` |

## 三、M465：akb 3 条焦点白盒精核（0 外部提交）

### 1. `backend/app/api/routes/admin_sso_operations.py:214` `execute_operation`

```python
@router.post("/admin/sso/identity-operations/{operation_id}/execute", ...)
async def execute_operation(operation_id: uuid.UUID, request: ExecuteRequest,
                            authorization: str | None = Header(default=None)):
    prefix = "AKB-Operation "
    if authorization is None or not authorization.startswith(prefix):
        raise HTTPException(401, ...)
    return await operations.execute(operation_id, authorization[len(prefix):], request.model_dump())
```

- **不是无鉴权**：路由不挂 `Depends`，但换成了**路由本地**的
  `Authorization: AKB-Operation <credential>` 载体；Cookie / 普通 bearer PAT
  都不能变成这个凭据（文件头注释明确写了这一点）。
- `app/sso/identity_operations.py:605` 的 `execute()` 逐项校验：
  `credential` 前缀与长度 → `sha256(credential)` 与库内
  `credential_hash` **`secrets.compare_digest`** → 操作窗口/安装 ID →
  provider 归属 revision/fingerprint → emergency 开关 → `verb` 必须在
  grant 的 `verbs` 内且不能是证据类动词 → `nonce` 重放（同 nonce 同请求
  返回缓存结果，不同请求 409）→ cohort 下标与 payload 约束。
- 同文件 `operation_login_challenge`（:378）同样要求 operation credential；
  `retire_operation`（:251）允许 operation credential 或
  `get_product_admin_mutation`；`admin_sso_operation_requests.py:208`
  `cancel_operation_request` 挂 `Depends(get_requesting_service_key)`。
- **结论：显式授予的有界操作凭据（capability），不是未授权管理接口。**
  规则层因"没有 `Depends`"把它当 authz 候选，是误报；本次先留白盒结论，
  不改规则。

### 2. `backend/app/api/routes/public.py:665` `renew_publication_view_grant`

- 续期必须携带**三段式** HMAC 授予（`_validate_view_grant_renewal`），
  two-field 旧格式只能取回、不能续期（注释与代码一致）；
- `_parse_view_grant()` 的消息体绑定 `slug`：`grant:{slug}:{issued}:{expires}`，
  HMAC-SHA256 常量时间比较，`expires <= issued + session_secs`、未来签发
  （>30s 时钟漂移）都拒绝；
- 续期还要重新走 `_resolve_with_access(..., increment_view=True,
  enforce_view_cap=True)`：发布是否存在、过期、密码、`max_views` 全部复查；
- 返回体只有新授予和剩余秒数，**不返回内容**。
- **结论：按设计的有界浏览凭据 + 计数复查，不是越权/续期绕过。**

### 3. `docker-compose.keycloak.yaml`

- 文件头：`OPTIONAL local Keycloak overlay`、`NOT part of the default stack`、
  `for developing/testing`；
- 固定值（`local-akb-dev-secret`、`admin/admin`、`product-admin-password`、
  `alice-password`）均标注为 throwaway local 值，realm 来自
  `deploy/keycloak-dev/akb-realm.json`；
- **结论：开发/测试默认凭据，不是生产泄露，不交单。** 该记录被
  `hardcoded_secret` 规则命中，是因为规则对 YAML 的 `#` 注释不做剥离，
  把注释里的示例键值当成了赋值 —— 属下一阶段可单独立项的降噪点
  （本轮不扩大改动面）。

### 4. 离线复扫（空 state，`--offline --offline-dedup`）

| 对象 | 修复前 | 修复后 |
|---|---|---|
| fojin `scan --auto` 根因 | 40（hash 2） | **38（hash 0）** |
| akb `scan --auto` 根因 | 34（authz 32 + secret 2） | 34（authz 32 + secret 2） |
| akb `LOCAL_LOOPBACK_ONLY`（旧 87 条逐条重判） | **18** | **0** |
| 两仓离线复扫记录 | — | 70（A=0 / B=70，全部 authz） |

> 离线模式 `--offline-dedup` 不可能给出 `ZERO_RECORD_FRESH`，所以复扫的
> A=0 不能单独证明"清零"；"fojin hash 2 → 0"由根因层（规则返回 False，
> 不再生成根因）与上面的逐函数判定共同证明。akb 的 2 条
> `hardcoded_secret` 在 `--max-roots 5` 下不占实扫名额；联网跑时若被保留，
> 白盒结论是"dev overlay 不交单"，需要下一阶段补 dev/overlay 降噪。

## 四、M466：门禁 `[352]` + 全套验证

`benchmarks/smoke_test_chains.py` 新增 `[352]`（纯离线，8 项）：

| 断言 | 结果 |
|---|---|
| `_PORT_MAP_RE` 命中裸 `8000:8000`，分组为 `(None, 8000, 8000)` | ✅ |
| 主 compose 公网映射 + `eval/` 回环 compose → `(False, "")` | ✅ |
| 纯回环 compose 仍判 `LOCAL_LOOPBACK_ONLY`（防放宽） | ✅ |
| 有 `k8s/deploy.yaml` 时不判单机 | ✅ |
| `hardcoded_secret` 不被同服务 `LOCAL_LOOPBACK_ONLY` 压掉 | ✅ |
| `cache_key` + `# nosec B324` 的 `sha1` → `False` | ✅ |
| `usedforsecurity=False` 的 `md5` → `False` | ✅ |
| `hashlib.md5(password)` → `True`（防放宽） | ✅ |

| 门禁 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,825 项断言**（v1.5.28 为 1,817） |
| `benchmarks/smoke_test_week1.py` | **SMOKE TEST PASS** |
| `benchmarks/smoke_test_week2.py` | **WEEK2 SMOKE TEST PASS** |
| `benchmarks/regress_owasp_rules.py`（改动前 / 改动后各跑一遍） | **两份输出逐字相同**（除耗时行）：A 方向 15 条、B 方向 0 条新增、`hash` vul→True 129 / safe→False 107、规则层合计 1,355 条 |
| `benchmarks/benchmark_javaseccode.py --offline` | OVERALL 54，**TPR 1.00 / FPR 0.00** |
| `benchmarks/benchmark_hellojavasec.py --offline` | 66 样本 / 命中 59（89.4%）/ **正确 58/58 = 100%**，1 条已知争议单列 |
| `benchmarks/benchmark_javaseclab.py --offline` | 夹具 `reference_repos/JavaSecLab` **未克隆 → 0 样本**（未验证，如实记录） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 地板全绿**（`decided` 均不低于地板） |
| `cli.py doctor` | **PASS（12 段全绿）** |

### OWASP 回归的改动前/后对照

`rule_detectors.py` 的改动**只影响 Python `hashlib.md5/sha1` 调用**（判据入口
是 `re.compile(r"hashlib\s*\.\s*(?:md5|sha1)\s*\(")`），而 OWASP BenchmarkJava
语料全是 Java（`MessageDigest` / `DigestUtils`），所以按构造即不可能命中。
实测两次输出（`git checkout HEAD -- core/agents/rule_detectors.py` 前后）：

```
A) vul→False 15 条（sqli 12 / pathtraver 3，与改动前逐条一致，非本轮新增）
B) safe→True  0 条（新增 0）
hash: vul→True 129  vul→None 0  safe→False 107   ← 前后完全一致
规则层合计判定 1,355 条                            ← 前后完全一致
```

> A 方向的 15 条在两版代码里**逐字相同**（`Compare-Object` 只差耗时行），
> 说明本轮没有引入新的静默放行；它们相对 2026-10-20 的文档基线是更早轮次
> 就已存在的历史项，不属本次改动面。

## 五、说明与遗留

- `--check-floor` 读的是 `benchmarks/results/*.json` 的历史 `decided`，本轮
  规则改动未重跑靶场；"不退化"的额外证据是上面 2,159 文件的回归面扫描
  （靶场零豁免）、4 条负向对照，以及 OWASP 语料前后逐字一致的 A/B 清单。
- `hardcoded_secret` 解除继承后，dev overlay 类凭据文件会更早进入候选；
  11-21 的两条（keycloak overlay / `deploy/keycloak-dev/broker-chain/exercise.py`）
  白盒结论均为测试夹具，建议下一阶段加"dev/overlay 默认凭据"降噪。
- 本轮不改 `_py_authz_guard_present` 对 `AKB-Operation` 载体的识别：
  akb 的 authz 记录仍全部留在 B 板（16 条 `AUTHZ_CLASS_OR_BASE_GUARD` +
  16 条 `UNVERIFIED_WILD_AUTHZ`），先积累白盒结论再决定规则形态。

## 六、提交清单

- `core/context/wild_noise.py` — M463 端口正则 / 跳过目录 / k8s 清单 /
  `hardcoded_secret` 豁免
- `core/agents/rule_detectors.py` — M464 弱哈希非安全用途判据
- `benchmarks/smoke_test_chains.py` — M466 `[352]` 8 项
- `STAGE_REPORT_2026-11-21_v1.5.29.md` — 本报告

> 验证用夹具 `reference_repos/BenchmarkJava-master` 为 OWASP 官方仓，
> `.gitignore` 已排除（`reference_repos/*`），不进入提交。
