"""Answers of /api/scdeck/stats/protect shaped like os-scdeck 0.79 gives them (protect.status(), protect.plan(), idspol.plan(), divert.status()):
two inner zones (LAN with Suricata, IoT under Zenarmor), the WAN, Divert active with one rule pf did not load, DECK policies at level
standard (still loading), a profile applied on LAN."""


def status(now):
    lan = {'key': 'lan', 'name': 'LAN', 'dev': 'em0', 'uplink': False, 'nets': ['192.168.1.0/24'], 'vlans': [], 'zenarmor': False, 'zen_tags': [], 'suricata': True, 'zen_vlans': False,
           'blocks': {'threat': {'by': 'suricata', 'state': 'ok', 'ips': True},
                      'web': {'by': 'unbound', 'state': 'ok', 'scope': 'zone', 'lists': ['atf', 'hgz003', 'hgz011'], 'own_lists': 0},
                      'app': {'by': 'l7', 'state': 'info'},
                      'dns': {'by': 'pf', 'state': 'ok', 'steps': {'rdr': True, 'dot': True, 'doh': False, 'dohcore': False}},
                      'intel': {'by': None, 'state': 'missing'}},
           'gaps': [], 'double': [], 'notes': []}
    iot = {'key': 'opt1', 'name': 'IoT', 'dev': 'em1', 'uplink': False, 'nets': ['192.168.2.0/24'], 'vlans': [], 'zenarmor': True, 'zen_tags': [], 'suricata': False, 'zen_vlans': False,
           'blocks': {'threat': {'by': 'zenarmor', 'state': 'zen'},
                      'web': {'by': 'zenarmor', 'state': 'zen', 'unbound': [], 'scope': None},
                      'app': {'by': 'zenarmor', 'state': 'zen'},
                      'dns': {'by': 'pf', 'state': 'gap', 'steps': {'rdr': False, 'dot': False, 'doh': False, 'dohcore': False}},
                      'intel': {'by': 'zenarmor', 'state': 'zen', 'pf': False}},
           'gaps': ['dns'], 'double': [], 'notes': []}
    wan = {'key': 'wan', 'name': 'WAN', 'dev': 'em3', 'uplink': True, 'nets': [], 'vlans': [], 'perimeter': 'suricata'}
    dnsbl = [{'uuid': '0b6f2d1e-0000-4000-8000-000000000001', 'enabled': True, 'descr': 'SC Deck: Stufe Standard', 'types': ['atf', 'hgz003', 'hgz011'], 'own_lists': 0,
              'lists': [], 'allowlists': [], 'blocklists': [], 'wildcards': [], 'source_nets': ['192.168.1.0/24']},
             {'uuid': '0b6f2d1e-0000-4000-8000-000000000002', 'enabled': False, 'descr': 'Meine alte Liste', 'types': ['hgz003'], 'own_lists': 1,
              'lists': ['https://example.org/list.txt'], 'allowlists': [], 'blocklists': [], 'wildcards': [], 'source_nets': []}]
    rule = lambda u, d, ifs, zen=False, wan_=False, divert=True: {'uuid': u, 'descr': d, 'ifs': ifs, 'zones': ifs, 'group': [], 'enabled': True, 'divert': divert, 'wan': wan_, 'zen': zen, 'open': True}
    return {'mode': 'mixed', 'suricata': {'enabled': True, 'ips': True, 'interfaces': ['lan', 'wan']},
            'zenarmor': {'installed': True, 'devices': ['em1']}, 'zones': [lan, iot], 'uplinks': [wan], 'dnsbl': [b for b in dnsbl if b['enabled']], 'dnsbl_all': dnsbl,
            'choose': [{'key': 'lan', 'name': 'LAN', 'dev': 'em0', 'uplink': False, 'skip': False}, {'key': 'opt1', 'name': 'IoT', 'dev': 'em1', 'uplink': False, 'skip': False},
                       {'key': 'opt2', 'name': 'Trunk', 'dev': 'em2', 'uplink': False, 'skip': True}, {'key': 'wan', 'name': 'WAN', 'dev': 'em3', 'uplink': True, 'skip': False}],
            'all_inside': [{'key': 'lan', 'nets': ['192.168.1.0/24']}, {'key': 'opt1', 'nets': ['192.168.2.0/24']}],
            'applied': {'lan': [{'id': 41, 'level': 'standard', 't': now - 7200, 'changes': [{'kind': 'dnsbl_level', 'list': None, 'name': 'SC Deck: Stufe Standard'}]}]},
            'divert': {'ids': {'enabled': True, 'mode': 'divert', 'listeners': 4, 'interfaces': ['lan', 'wan']}, 'running': True, 'listening': 4, 'cpus': 4,
                       'wans': [{'key': 'wan', 'name': 'WAN'}], 'ours': [],
                       'in': [rule('11111111-1111-4111-8111-111111111111', 'LAN zu allem', ['lan']),
                              rule('22222222-2222-4222-8222-222222222222', 'IoT ins Internet', ['opt1'], zen=True, divert=False),
                              rule('33333333-3333-4333-8333-333333333333', 'Gaeste ueber Gateway', ['lan'], divert=False)],
                       'marked': 1, 'legacy': [], 'zen_zones': ['opt1'], 'zen_layer': False,
                       'skipped': [{'uuid': '33333333-3333-4333-8333-333333333333', 'descr': 'Gaeste ueber Gateway', 'ifs': ['lan'], 'why': 'off'}], 'portal': [], 'extra': [],
                       'state': 'active', 'pending': None, 'entry': 40, 'last': {'t': now - 86400, 'state': 'active', 'error': '', 'started': now - 86400},
                       'guarded': [], 'gaps': [], 'netmap_risk': False, 'crashed': False},
            'idspol': {'ids': {'enabled': True, 'mode': 'divert'}, 'ours': [{'uuid': 'p1', 'description': 'SC Deck: Malware und C2'}, {'uuid': 'p2', 'description': 'SC Deck: Exploits'}],
                       'level': 'standard', 'owner': [], 'entry': 42, 'entry_t': now - 120, 'reload': {'start': now - 110, 'done': now - 3600}},
            'counts': {'zones': 2, 'gaps': 1, 'double': 0}}


def plan(zone, level, now):
    if zone == 'opt1':
        return {'zone': 'opt1', 'name': 'IoT', 'level': level, 'title': 'Schutzprofil %s für IoT' % level.capitalize(),
                'changes': [{'kind': 'dnsbl_level', 'list': None, 'name': 'SC Deck: Stufe Streng', 'nets': ['192.168.2.0/24'], 'from': [], 'add_types': ['hgz011', 'hgz005', 'hgz014'],
                             'allow': 0, 'block': 0, 'urls': 0, 'wild': 0, 'rest': []},
                            {'kind': 'dns', 'step': 'rdr'}, {'kind': 'dns', 'step': 'dot'}, {'kind': 'dns', 'step': 'doh', 'core': True}],
                'notes': ['Zenarmor bleibt für Bedrohungen, Web-Kategorien und Anwendungen zuständig (Zenarmor › Richtlinien); die Unbound-Liste ergänzt es als zweite Schicht.'],
                'memory': {'now': 310, 'after': 2400, 'avail': 1900, 'state': 'block', 'unknown': ['hgz014']},
                'blocked': 'Zu wenig Speicher: Der Aufbau der Unbound-Blocklisten bräuchte danach etwa 2400 MB, frei sind 1900 MB.'}
    if zone != 'lan':
        return {'error': 'Unbekannte Zone'}
    if level == 'standard':
        return {'zone': 'lan', 'name': 'LAN', 'level': level, 'title': 'Schutzprofil Standard für LAN', 'changes': [], 'notes': []}
    return {'zone': 'lan', 'name': 'LAN', 'level': level, 'title': 'Schutzprofil %s für LAN' % level.capitalize(),
            'changes': [{'kind': 'dnsbl_level', 'list': '0b6f2d1e-0000-4000-8000-000000000001', 'name': 'SC Deck: Stufe %s' % level.capitalize(), 'nets': ['192.168.1.0/24'],
                         'from': ['Meine alte Liste'], 'add_types': ['hgz009'], 'allow': 2, 'block': 0, 'urls': 1, 'wild': 0, 'rest': []},
                        {'kind': 'dns', 'step': 'doh', 'core': True}],
            'notes': [], 'memory': {'now': 310, 'after': 420, 'avail': 1900, 'state': 'ok', 'unknown': []}}


def ids_plan(level):
    body = {'content': 'signature_severity.critical,signature_severity.major,confidence.high', 'rulesets': 'emerging-malware.rules,emerging-exploit.rules', 'action': 'drop'}
    if level == 'standard':
        return {'level': level, 'changes': [], 'notes': [], 'ids': {'enabled': True, 'mode': 'divert'}, 'current': 'standard'}
    return {'level': level, 'changes': [{'kind': 'set', 'goal': 'malware', 'uuid': 'p1', 'body': body}, {'kind': 'add', 'goal': 'tor', 'body': dict(body, rulesets='tor.rules')}],
            'notes': [], 'ids': {'enabled': True, 'mode': 'divert'}, 'current': 'standard'}
