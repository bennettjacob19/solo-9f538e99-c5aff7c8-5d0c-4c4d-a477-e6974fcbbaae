# 双出口路由变更预检 API（route-precheck）

改动 Linux 双出口策略路由前，值班员把**变更前后**两份 `ip -j -4 rule show` 和
`ip -j -4 route show table all` 的 JSON，连同源、目的 IPv4 CIDR 一起提交给
`POST /precheck`；接口返回**转发结果有变化的地址对**，按（变更前结果 → 变更后结果）
分组，每组给出十进制字符串计数、一对示例地址和两侧的选路依据。

计数是**符号化**完成的：引擎把 源CIDR × 目的CIDR 的地址空间递归切成
"两侧结果都恒定"的矩形，再按矩形面积（2 的幂）求和。计算量只取决于策略规模，
与地址数量无关，`0.0.0.0/0 × 0.0.0.0/0`（2^64 对）也能秒出。

## 启动

```bash
docker compose up --build      # 监听 0.0.0.0:8000
# 或本地： pip install -r requirements.txt && uvicorn app.main:app --port 8000
```

打开 <http://localhost:8000/docs>（Swagger UI），`POST /precheck` 已预填示例，
直接 "Try it out" 即可。`GET /` 重定向到 `/docs`，`GET /healthz` 用于健康检查。

## 输入

```json
{
  "source_cidr": "10.0.0.0/8",
  "destination_cidr": "198.51.100.0/24",
  "before": {"rules": [/* ip -j -4 rule show 的 JSON 数组 */],
             "routes": [/* ip -j -4 route show table all 的 JSON 数组 */]},
  "after":  {"rules": [...], "routes": [...]}
}
```

* 两个 CIDR 都可以是 `0.0.0.0/0`（也接受 `all`/`default` 写法；带主机位会被归一化）。
* `rules`/`routes` 直接粘贴两条 `ip -j` 命令解析后的 JSON 数组即可。

## 选路语义（与任务约定一致）

* **略过 local 表和指向它的规则**；其余规则按**互异的优先级从小到大**依次查表。
* 规则只用 `src`/`dst` 选择器匹配源和目的。
* 表内前缀唯一，按**最长前缀**匹配；支持单路径 `unicast`（`dev` + 可选
  `gateway`）、`throw`、`blackhole`。
* 查无路由或命中 `throw` → 继续查下一条规则；`blackhole` → 立即丢弃；
  所有规则耗尽 → 结果记为 `no_route`。
* 转发结果的同一性 = 出口网卡 + 下一跳的组合（`dev`, `gateway`），另有
  `blackhole` 与 `no_route` 两类；不比较 preferred-src、metric 等属性。

## 输出

```json
{
  "summary": {"total_pairs": "...", "changed_pairs": "...", "unchanged_pairs": "...",
              "group_count": 2, "source_cidr": "...", "destination_cidr": "..."},
  "groups": [{
    "before": {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"},
    "after":  {"type": "blackhole"},
    "count": "2147483648",
    "example": {"source": "10.0.0.0", "destination": "198.51.100.128"},
    "basis_before":  {"rule_priority": 100, "table": "100", "route_prefix": "0.0.0.0/0",
                      "route_type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"},
    "basis_after":   {"rule_priority": 100, "table": "100", "route_prefix": "198.51.100.128/25",
                      "route_type": "blackhole"}
  }]
}
```

只报告结果有变化的地址对；未变化的只体现在 `summary.unchanged_pairs` 总数里。

## 错误处理

* `400`：输入合法 JSON 但超出支持模型（见下"限制"），`detail` 说明原因与位置
  （如 `before route #3: unsupported route type 'prohibit' ...`）。
* `422`：请求体不符合 schema（缺字段、类型错误等）。

## 已实现

* FastAPI 服务：`POST /precheck`、`GET /`（跳转 /docs）、`GET /healthz`，
  /docs 预填双出口示例。
* 符号化决策引擎 `app/routing.py`（纯标准库）：规则排序与 src/dst 匹配、
  最长前缀、unicast/throw/blackhole、throw/查无路由继续查、blackhole 立即丢弃、
  local 表及指向它的规则跳过、表名/表号归一（`main`/`253`、`100`/`"100"`、
  自定义名按名匹配）。
* 按（前结果 → 后结果）分组：十进制字符串计数、示例地址对、两侧选路依据；
  结果区分 (dev, gateway) 组合、blackhole、no_route。
* 输入校验：多路径（`nexthops`）、`nhid`、encap、非 unicast/throw/blackhole 路由、
  规则带 fwmark/iif/tos 等额外属性或非 lookup 动作、优先级重复、同表前缀重复、
  IPv6、非法 gateway、unicast 缺 `dev` 等一律报 400。
* Dockerfile + docker-compose.yml（`docker compose up --build` 即可启动）。
* 测试：`tests/`（pytest，32 例）。

## 已验证

* `python3 -m pytest`：32 例全部通过（Python 3.11，fastapi 0.165 / pydantic 2.14）。
  包括：网关/网卡变化计数、黑洞切分目的前缀、throw 穿透与 blackhole 不穿透、
  查无路由继续查、local 表跳过、最长前缀、规则 src/dst 选择器切分地址空间、
  `/0 × /0` = 2^64 计数、各类非法输入报错。
* **随机对拍**：`test_symbolic_engine_matches_bruteforce` 用随机策略（含 throw/
  blackhole/local 噪声）在 64×64 地址空间上把符号引擎与独立的逐地址暴力查找
  逐一比对——分组计数、示例地址归属、依据类型完全一致。
* 端到端冒烟：uvicorn 起服后 curl `/docs`、`/precheck`（示例与 `/0 × /0`）、
  400 错误路径均符合预期。

## 未完成 / 限制

* 仅 IPv4；规则仅支持 src/dst 选择器 + 查表动作（fwmark/iif/oif/tos/uidrange/
  sport/dport/ipproto/not/goto 等提交即 400）。
* 路由仅支持单路径 unicast/throw/blackhole；multipath、nexthop 对象（nhid）、
  unreachable/prohibit/nat、encap 等提交即 400。
* 规则优先级必须互异、同表前缀必须唯一（违反即 400，不猜测语义）。
* 结果同一性不看 preferred-src、metric、MTU 等；经 throw/查无路由继续查找时，
  "选路依据"只记录最终决策点（规则/表/前缀），不记录中间跳过的表。
* 决策单元格上限 100,000（防御病态碎化输入，超限报 400）。
* 本环境无 docker，Dockerfile/compose 未实际构建过，仅经过静态核对。
