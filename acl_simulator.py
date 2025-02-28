import ipaddress
import time
from textfsm import TextFSM
from functools import lru_cache


class ACLOptimizer:
    """ACL规则优化处理核心类"""

    # 预定义规则优先级映射
    RULE_PRIORITY_MAP = {
        frozenset({'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort'}): 'A',
        frozenset({'SourceIP', 'DestinationIP', 'SourcePort'}): 'B',
        frozenset({'SourceIP', 'DestinationIP', 'DestinationPort'}): 'C',
        frozenset({'SourceIP', 'DestinationIP'}): 'D',
        frozenset({'SourceIP', 'SourcePort', 'DestinationPort'}): 'E',
        frozenset({'SourceIP', 'SourcePort'}): 'F',
        frozenset({'SourceIP', 'DestinationPort'}): 'G',
        frozenset({'DestinationIP', 'SourcePort', 'DestinationPort'}): 'H',
        frozenset({'DestinationIP', 'DestinationPort'}): 'I',
        frozenset({'DestinationIP', 'SourcePort'}): 'J',
        frozenset({'SourceIP'}): 'K',
        frozenset({'DestinationIP'}): 'L',
        frozenset(): 'M'
    }
    PROTOCOL_HIERARCHY = {
        'ip': {'tcp', 'udp', 'icmp', 'gre', 'esp', 'igmp'},  # IP协议包含的子协议
        'tcp': set(),
        'udp': set(),
        'icmp': set(),
        'gre': set(),
        'esp': set(),
        'igmp': set()
    }

    # 规则包含关系配置
    RULE_CONTAIN_MAP = {
        'A': {'contain': ['A'], 'contained': ['B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J','K','L']},
        'B': {'contain': ['A', 'B'], 'contained': ['D','F','J','K','L']},
        'C': {'contain': ['A','C'], 'contained': ['D','G','I','K','L']},
        'D': {'contain': ['A','B','C','D'], 'contained': ['K', 'L']},
        'E': {'contain': ['A', 'E'], 'contained': ['F','G','K']},
        'F': {'contain': ['A','B','E','F'], 'contained': ['K']},
        'G': {'contain': ['A','C','E','G'], 'contained': ['K']},
        'H': {'contain': ['A', 'H'], 'contained': ['I','J','L']},
        'I': {'contain': ['A','C','H','I'], 'contained': ['L']},
        'J': {'contain': ['A', 'B', 'H','J'], 'contained': ['L']},
        'K': {'contain': ['A','B','C','D','E','F','G','K'], 'contained': []},
        'L': {'contain': ['A','B','C','D','H','I','J','L'], 'contained': []},
        'M': {'contain': [], 'contained': []},
    }

    def __init__(self):
        self._matcher_cache = {}

    @lru_cache(maxsize=1024)
    def get_network(self, address, wildcard):
        """缓存网络对象计算"""
        if not address: return None
        wildcard = wildcard or '0.0.0.0'
        return ipaddress.IPv4Network(
            f"{address}/{self.wildcard_to_cidr(wildcard)}",
            strict=False
        )

    def wildcard_to_cidr(self, wildcard):
        """增强通配符转换逻辑"""
        if wildcard in ('', '0.0.0.0'): return 32
        octets = list(map(int, wildcard.split('.')))
        return 32 - sum(bin(octet).count('1') for octet in octets)

    def determine_rule_type(self, rule):
        """优化版规则类型判断"""
        present_fields = frozenset(
            k for k, v in rule.items()
            if v and k in {'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort'}
        )
        return self.RULE_PRIORITY_MAP.get(present_fields, 'M')

    class RuleMatcher:
        """规则匹配器封装类"""

        def __init__(self, optimizer, rule):
            self.optimizer = optimizer
            self.rule = rule
            self.rule_type = optimizer.determine_rule_type(rule)
            # 预处理网络对象
            self.src_net = optimizer.get_network(
                rule['SourceIP'],
                rule.get('SourceWildcard', '0.0.0.0')
            )
            self.dst_net = optimizer.get_network(
                rule['DestinationIP'],
                rule.get('DestinationWildcard', '0.0.0.0')
            )

        def _protocol_contain(self, other):
            """双向协议包含检查"""
            # 相同协议
            if self.rule['Protocol'] == other.rule['Protocol']:
                return True

            # 当前协议是父协议
            if self.rule['Protocol'] == 'ip' and \
                    other.rule['Protocol'] in self.optimizer.PROTOCOL_HIERARCHY['ip']:
                return True

            # 对方协议是父协议
            if other.rule['Protocol'] == 'ip' and \
                    self.rule['Protocol'] in self.optimizer.PROTOCOL_HIERARCHY['ip']:
                return True

            return False

        def conflict_check(self, other):
            """双向冲突检测"""
            # 协议不兼容
            if not self._protocol_contain(other):
                return False

            # 动作相同不构成冲突
            if self.rule['Action'] == other.rule['Action']:
                return False

            # 网络重叠检测
            src_overlap = self._network_overlap(self.src_net, other.src_net)
            dst_overlap = self._network_overlap(self.dst_net, other.dst_net)
            port_conflict = self._port_conflict(other)

            return (src_overlap and dst_overlap) and port_conflict

        def _network_overlap(self, net1, net2):
            """网络重叠判断"""
            if not net1 or not net2:
                return True  # 任意一方未指定视为全局匹配
            return net1.overlaps(net2)

        def _port_conflict(self, other):
            """端口冲突判断"""

            def _parse_port(port_str):
                if port_str in ('', 'any'):
                    return (0, 65535)
                if 'eq' in port_str:
                    port = int(port_str.split()[-1])
                    return (port, port)
                # 添加范围解析逻辑
                return (0, 65535)  # 示例默认值

            src_port_self = _parse_port(self.rule['SourcePort'])
            src_port_other = _parse_port(other.rule['SourcePort'])
            dst_port_self = _parse_port(self.rule['DestinationPort'])
            dst_port_other = _parse_port(other.rule['DestinationPort'])

            src_conflict = max(src_port_self[0], src_port_other[0]) <= min(src_port_self[1], src_port_other[1])
            dst_conflict = max(dst_port_self[0], dst_port_other[0]) <= min(dst_port_self[1], dst_port_other[1])

            return src_conflict or dst_conflict

        def _protocol_match(self, other):
            """增强协议匹配判断"""
            # 当前规则协议与新规则协议相同
            if self.rule['Protocol'] == other.rule['Protocol']:
                return True

            # 当前规则协议为ip且新协议属于ip子协议
            if self.rule['Protocol'] == 'ip' and \
                    other.rule['Protocol'] in self.optimizer.PROTOCOL_HIERARCHY['ip']:
                return True

            # 新规则协议为ip且当前协议属于ip子协议
            if other.rule['Protocol'] == 'ip' and \
                    self.rule['Protocol'] in self.optimizer.PROTOCOL_HIERARCHY['ip']:
                return False  # 仅当当前规则是父协议时才返回True

            return False

        def compare_ports(self, other, check_src=True, check_dst=True):
            def _port_match(a, b):
                if a in ('', 'any') or b in ('', 'any'):
                    return True
                return a == b

            if check_src and not _port_match(self.rule['SourcePort'], other.rule['SourcePort']):
                return False
            if check_dst and not _port_match(self.rule['DestinationPort'], other.rule['DestinationPort']):
                return False
            return True

        def contains(self, other):
            # 协议兼容性检查
            if not self._protocol_match(other):
                return False

            # 类型兼容性检查
            if other.rule_type not in self.optimizer.RULE_CONTAIN_MAP[self.rule_type]['contain']:
                return False

            # 端口匹配检查
            if not self.compare_ports(other):
                return False

            # 网络包含判断
            src_contain = (self.src_net is None) or (
                other.src_net and other.src_net.subnet_of(self.src_net)
            )
            dst_contain = (self.dst_net is None) or (
                other.dst_net and other.dst_net.subnet_of(self.dst_net)
            )
            return src_contain and dst_contain

def _handle_contain_rule(exist_matcher, new_rule):
    """处理被包含情况"""
    if exist_matcher.rule['Action'] == new_rule['Action']:
        print(f"📦 规则 {exist_matcher.rule['RuleID']} 包含新规则，建议合并")
        return int(exist_matcher.rule['RuleID'])
    else:
        print(f"⚔️ 与规则 {exist_matcher.rule['RuleID']} 存在动作冲突")
        return int(exist_matcher.rule['RuleID']) - 1


def _get_last_rule_id(rules):
    return max((int(r['RuleID']) for r in rules), default=0)

def optimize_rule_insertion(new_rule, existing_rules):
    """增强版规则插入逻辑"""
    optimizer = ACLOptimizer()
    new_matcher = optimizer.RuleMatcher(optimizer, new_rule)

    conflict_rules = []
    contain_rules = []
    contained_rules = []

    # 第一阶段：冲突检测
    for rule in existing_rules:
        exist_matcher = optimizer.RuleMatcher(optimizer, rule)
        # 双向冲突检测
        if exist_matcher.conflict_check(new_matcher) or new_matcher.conflict_check(exist_matcher):
            conflict_rules.append(rule)

    # 第二阶段：包含关系检测
    sorted_rules = sorted(
        existing_rules,
        key=lambda x: int(x['RuleID']),
        reverse=True
    )

    for rule in sorted_rules:
        exist_matcher = optimizer.RuleMatcher(optimizer, rule)

        # 被现有规则包含
        if exist_matcher.contains(new_matcher):
            return _handle_contain_rule(exist_matcher, new_rule)

        # 包含现有规则
        if new_matcher.contains(exist_matcher):
            contained_rules.append(rule)

    # 第三阶段：处理被包含规则
    if contained_rules:
        highest_contained = max(int(r['RuleID']) for r in contained_rules)
        return highest_contained + 1

    # 第四阶段：处理冲突规则
    if conflict_rules:
        min_conflict_id = min(int(r['RuleID']) for r in conflict_rules)
        print(f"⚠️ 与规则 {min_conflict_id} 存在冲突")
        return max(min_conflict_id - 1, 0)

    # 默认插入末尾
    return _get_last_rule_id(existing_rules) + 1





# 示例使用
if __name__ == '__main__':
    # 模拟数据加载
    def load_rules(file_path):
        with open(file_path) as f:
            acl = f.read()
        with open('templates/dis_acl.textfsm') as t:
            return TextFSM(t).ParseTextToDicts(acl)


    # 构造测试规则
    test_rule = {
        'Action': 'permit',
        'DestinationIP': '172.18.19.224',
        'DestinationPort': '443',
        'DestinationWildcard': '0.0.0.0',
        'Protocol': 'udp',
        'SourceIP': '',
        'SourcePort': '',
        'SourceWildcard': ''
    }

    # 执行优化插入
    start = time.time()
    existing_rules = load_rules('acl.txt')
    suggested_id = optimize_rule_insertion(test_rule, existing_rules)
    print(f"建议插入位置: RuleID {suggested_id}")
    print(f"耗时: {time.time() - start:.4f}s")