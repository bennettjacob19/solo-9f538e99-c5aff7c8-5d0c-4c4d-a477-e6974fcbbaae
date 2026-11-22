# 双出口路由变更预检 / 死配置审计 API（route-precheck）

改动 Linux 双出口策略路由前，值班员把 `ip -j -4 rule show` 和
`ip -j -4 route show table all` 的 JSON，连同源、目的 IPv4 CIDR 一起提交：

* `POST /precheck`：对比**变更前后**两份快照，返回转发结果有变化的地址对，
  按（变更前结果 → 变更后结果）分组，每组给出十进制字符串计数、一对示例地址和
  两侧的选路依据。
* `POST /audit-unused`：对**一份**快照逐条试算"删掉这条规则/路由会怎样"，
  按真实查表顺序模拟删除后的转发，只把删除后整个范围内（出口网卡, 下一跳）组合、
  黑洞、无路由结果全部不变的项列为可清理，返回原数组索引、结论和可核对的依据。

两个接口的计算都是**符号化**完成的：引擎把 源CIDR × 目的CIDR 的地址空间递归切成
"结果恒定"的矩形（决策单元格），再按矩形面积（2 的幂）求和。计算量只取决于策略
规模，与地址数量无关，`0.0.0.0/0 × 0.0.0.0/0`（2^64 对）也能秒出。

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

## POST /audit-unused：死配置审计

```json
{
  "source_cidr": "10.0.0.0/8",
  "destination_cidr": "0.0.0.0/0",
  "rules":  [/* ip -j -4 rule show 的 JSON 数组 */],
  "routes": [/* ip -j -4 route show table all 的 JSON 数组 */]
}
```

接口对 `rules`/`routes` 的**每一个原始下标**给出一条结论（按原数组顺序，下标即
返回的 `index`，可直接对照 `ip -j` 输出核对）。判定逻辑：

1. 先把查询范围符号化切成决策单元格，按真实规则优先级顺序追踪每条规则/路由被哪些
   地址对实际命中（`matched_pairs`、`sample`）。
2. 对每个**被命中过**的项，构造"删掉该项"的快照，在全部单元格上重新查表，统计
   转发结果发生变化的地址对（`changed_pairs_after_removal`）。
3. 只有 `matched_pairs > 0` **且** `changed_pairs_after_removal == 0` 才判
   `cleanable: true`。

`reason` 取值：

| reason | 含义 |
| --- | --- |
| `cleanable` | 范围内确实被命中，且删除后全范围（dev, gateway）组合、blackhole、no_route 结果全部不变 |
| `not_referenced_in_scope` | 查询范围内没有任何地址对命中该项（被遮蔽/选择器不覆盖）。**不会误报为安全**——窄查询下看不到的配置可能在范围外仍承载流量，需扩大 CIDR 再查 |
| `forwarding_changes` | 删除后范围内至少一个地址对的转发结果改变；`evidence.first_change` 给出首个变化单元格、删除前后结果与两侧选路依据 |
| `local_table_excluded` | local 表中的路由、指向 local 表的规则：沿用既有语义不参与建模，显式排除而非判安全 |

关键语义与 `/precheck` 完全一致：

* **throw**：作为某表最长前缀被命中时计入使用；它让查表继续到下一条规则。删掉它若
  暴露同表更不具体的路由从而改变出口，则 `forwarding_changes`；若穿透后的落点与现状
  完全相同，则可判 `cleanable`（这是基于同一查表语义的可证明结论，不是"没命中"）。
* **blackhole**：实际丢弃流量的黑洞删除后会变成 unicast/no_route，必然
  `forwarding_changes`；永远查不到的黑洞只报 `not_referenced_in_scope`。
* **local 表与指向 local 的规则**：直接标记 `local_table_excluded`，不参与试算。
* 结果同一性 = 出口网卡 + 下一跳（`dev`, `gateway`）组合，另加 `blackhole`、
  `no_route` 两类；gateway 不同（即使 dev 相同）也算变化。

输出示例（节选）：

```json
{
  "summary": {"source_cidr": "10.0.0.0/8", "destination_cidr": "0.0.0.0/0",
              "total_pairs": "72057594037927936",
              "rules_total": 4, "rules_cleanable": 1,
              "routes_total": 3, "routes_cleanable": 0},
  "rules": [{
    "index": 1, "kind": "rule",
    "identity": {"priority": 100, "src": "10.0.0.0/8", "table": "100"},
    "cleanable": true, "reason": "cleanable",
    "evidence": {"matched_pairs": "72057594037927936",
                 "sample": {"source": "10.0.0.0", "destination": "0.0.0.0"},
                 "changed_pairs_after_removal": "0",
                 "sample_result_before_removal": {"type": "unicast", "dev": "eth1",
                                                  "gateway": "198.51.100.1"},
                 "sample_basis_before_removal": {"rule_priority": 100, "table": "100",
                                                 "route_prefix": "0.0.0.0/0", ...}}
  }],
  "routes": [ ... ]
}
```

## 错误处理

* `400`：输入合法 JSON 但超出支持模型（见下"限制"），`detail` 说明原因与位置
  （如 `before route #3: unsupported route type 'prohibit' ...`）。
* `422`：请求体不符合 schema（缺字段、类型错误等）。

## 已实现

* FastAPI 服务：`POST /precheck`、`POST /audit-unused`、`GET /`（跳转 /docs）、
  `GET /healthz`，/docs 两个接口均预填示例。
* 符号化决策引擎 `app/routing.py`（纯标准库）：规则排序与 src/dst 匹配、
  最长前缀、unicast/throw/blackhole、throw/查无路由继续查、blackhole 立即丢弃、
  local 表及指向它的规则跳过、表名/表号归一（`main`/`253`、`100`/`"100"`、
  自定义名按名匹配）。
* `/precheck` 按（前结果 → 后结果）分组：十进制字符串计数、示例地址对、两侧选路依据；
  结果区分 (dev, gateway) 组合、blackhole、no_route。
* `/audit-unused` 逐条规则/路由试算删除后的全范围转发，输出原始数组索引、
  `cleanable`/`reason` 结论与可核对依据（命中对数、示例对、删除后变化对数、
  首个变化单元格的前后结果与依据）；范围内未命中项只报 `not_referenced_in_scope`，
  local 项报 `local_table_excluded`，均不会误判为可清理。
* 输入校验：多路径（`nexthops`）、`nhid`、encap、非 unicast/throw/blackhole 路由、
  规则带 fwmark/iif/tos 等额外属性或非 lookup 动作、优先级重复、同表前缀重复、
  IPv6、非法 gateway、unicast 缺 `dev` 等一律报 400。
* Dockerfile + docker-compose.yml（`docker compose up --build` 即可启动）。
* 测试：`tests/`（pytest，54 例）。

## 已验证

* `python3 -m pytest`：54 例全部通过（Python 3.11，fastapi 0.165 / pydantic 2.14）。
  包括：网关/网卡变化计数、黑洞切分目的前缀、throw 穿透与 blackhole 不穿透、
  查无路由继续查、local 表跳过、最长前缀、规则 src/dst 选择器切分地址空间、
  `/0 × /0` = 2^64 计数、各类非法输入报错。
* **审计专项**：交错规则（同表重复规则、遮蔽、中间承载规则）、throw 的两种情形
  （遮蔽同表路由→不可删；穿透落点不变→可删）、blackhole（承载/不可达/后表兜底）、
  嵌套前缀与嵌套 src 选择器、查询范围纪律（范围外存活的项不会在窄查询下被判安全）、
  同 (dev, gateway) 兜底可删而 gateway 不同即不可删。
* **随机对拍**：两个对拍测试分别用随机策略在 64×64 地址空间上把符号引擎与独立的
  逐地址暴力查找逐一比对——`/precheck` 的分组计数、示例归属、依据，以及
  `/audit-unused` 每个下标的 used/cleanable 结论和命中计数完全一致（共 110 轮）。
* 端到端冒烟：uvicorn 起服后 curl `/healthz`、`/audit-unused`（含 `/8 × /0`
  = 2^56 对的符号化计数）、400/422 错误路径均符合预期。

## 未完成 / 限制

* 仅 IPv4；规则仅支持 src/dst 选择器 + 查表动作（fwmark/iif/oif/tos/uidrange/
  sport/dport/ipproto/not/goto 等提交即 400）。
* 路由仅支持单路径 unicast/throw/blackhole；multipath、nexthop 对象（nhid）、
  unreachable/prohibit/nat、encap 等提交即 400。
* 规则优先级必须互异、同表前缀必须唯一（违反即 400，不猜测语义）。
* 结果同一性不看 preferred-src、metric、MTU 等；经 throw/查无路由继续查找时，
  "选路依据"只记录最终决策点（规则/表/前缀），不记录中间跳过的表。
* `/audit-unused` 的结论只对提交的 CIDR 范围负责：范围外的配置影响不可见，
  未命中项一律不给"可清理"结论；需要全局结论时提交 `0.0.0.0/0 × 0.0.0.0/0`。
  审计是**逐条单项删除**试算，不推导同时删多项的组合效应。
* 决策单元格上限 100,000（防御病态碎化输入，超限报 400）。
* 本环境无 docker，Dockerfile/compose 未实际构建过，仅经过静态核对。
