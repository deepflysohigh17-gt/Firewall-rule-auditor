# Firewall Audit: sample_rules.txt

Rules analyzed: **12**  |  Findings: **13**

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 4 |
| Medium | 1 |
| Low | 7 |

## F001 · CRITICAL · any_any

**Chain:** filter/FORWARD  ·  **Line:** 16

```
-A FORWARD -j ACCEPT
```

**Finding:** Accepts all traffic: any source, any destination, any protocol, any port.

## F002 · HIGH · default_allow_policy

**Chain:** filter/INPUT  ·  **Line:** 3

```
:INPUT ACCEPT
```

**Finding:** Default policy for INPUT is ACCEPT: anything not explicitly blocked is allowed (default-allow instead of default-deny).

## F003 · HIGH · shadowed_conflict

**Chain:** filter/INPUT  ·  **Line:** 10

```
-A INPUT -s 10.66.0.5/32 -p tcp -m tcp --dport 22 -m comment --comment "block compromised host" -j DROP
```

**Finding:** Never reached: line 8 matches all of this traffic first and applies ACCEPT, so this rule's DROP never takes effect.

**Caused by:** `line 8: -A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -m comment --comment "SSH from corp" -j ACCEPT`

## F004 · HIGH · sensitive_service_exposed

**Chain:** filter/INPUT  ·  **Line:** 12

```
-A INPUT -p tcp -m tcp --dport 3389 -j ACCEPT
```

**Finding:** RDP reachable from any source address.

## F005 · HIGH · shadowed_conflict

**Chain:** filter/FORWARD  ·  **Line:** 17

```
-A FORWARD -s 172.16.0.0/12 -d 10.0.0.0/8 -j DROP
```

**Finding:** Never reached: line 16 matches all of this traffic first and applies ACCEPT, so this rule's DROP never takes effect.

**Caused by:** `line 16: -A FORWARD -j ACCEPT`

## F006 · MEDIUM · all_ports_from_source

**Chain:** filter/INPUT  ·  **Line:** 14

```
-A INPUT -s 203.0.113.0/24 -m comment --comment "partner VPN" -j ACCEPT
```

**Finding:** Accepts every protocol and port from 203.0.113.0/24; consider limiting to the services actually needed.

## F007 · LOW · redundant

**Chain:** filter/INPUT  ·  **Line:** 9

```
-A INPUT -s 10.20.30.0/24 -p tcp -m tcp --dport 22 -m comment --comment "SSH from ops" -j ACCEPT
```

**Finding:** Never reached: line 8 already matches all of this traffic with the same action (ACCEPT).

**Caused by:** `line 8: -A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -m comment --comment "SSH from corp" -j ACCEPT`

## F008 · LOW · unused

**Chain:** filter/INPUT  ·  **Line:** 9

```
-A INPUT -s 10.20.30.0/24 -p tcp -m tcp --dport 22 -m comment --comment "SSH from ops" -j ACCEPT
```

**Finding:** Hit counter is 0. Verify over a long window (counters reset on reboot/reload) before removing.

## F009 · LOW · unused

**Chain:** filter/INPUT  ·  **Line:** 10

```
-A INPUT -s 10.66.0.5/32 -p tcp -m tcp --dport 22 -m comment --comment "block compromised host" -j DROP
```

**Finding:** Hit counter is 0. Verify over a long window (counters reset on reboot/reload) before removing.

## F010 · LOW · unused

**Chain:** filter/INPUT  ·  **Line:** 13

```
-A INPUT -s 192.168.50.0/24 -p tcp -m multiport --dports 3306,5432 -j ACCEPT
```

**Finding:** Hit counter is 0. Verify over a long window (counters reset on reboot/reload) before removing.

## F011 · LOW · redundant

**Chain:** filter/INPUT  ·  **Line:** 15

```
-A INPUT -s 203.0.113.17/32 -p tcp -m tcp --dport 8080 -j ACCEPT
```

**Finding:** Never reached: line 14 already matches all of this traffic with the same action (ACCEPT).

**Caused by:** `line 14: -A INPUT -s 203.0.113.0/24 -m comment --comment "partner VPN" -j ACCEPT`

## F012 · LOW · unused

**Chain:** filter/INPUT  ·  **Line:** 15

```
-A INPUT -s 203.0.113.17/32 -p tcp -m tcp --dport 8080 -j ACCEPT
```

**Finding:** Hit counter is 0. Verify over a long window (counters reset on reboot/reload) before removing.

## F013 · LOW · unused

**Chain:** filter/FORWARD  ·  **Line:** 17

```
-A FORWARD -s 172.16.0.0/12 -d 10.0.0.0/8 -j DROP
```

**Finding:** Hit counter is 0. Verify over a long window (counters reset on reboot/reload) before removing.
