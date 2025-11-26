# SDN Controller - Complete API Guide

## REST API Endpoints

Base URL: `http://localhost:8080/api`

### 1. View Network Information

#### Get Topology
```bash
curl http://localhost:8080/api/topology
```

**Response:**
```json
{
  "switches": {
    "1": {
      "dpid": 1,
      "address": "('127.0.0.1', 12345)"
    }
  },
  "hosts": {
    "00:00:00:00:00:01": {
      "mac": "00:00:00:00:00:01",
      "switch": 1,
      "port": 1
    }
  }
}
```

#### Get Statistics
```bash
curl http://localhost:8080/api/stats
```

**Response:**
```json
{
  "switches": 1,
  "hosts": 3,
  "intents": 2,
  "active_intents": 1
}
```

#### Get Flow Table
```bash
curl http://localhost:8080/api/flows/1
```

---

## 2. Intent Management

### Get All Intents
```bash
curl http://localhost:8080/api/intents
```

---

## 3. Block Traffic (Block Route)

### Block h1 → h2
```bash
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "block",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02",
    "description": "Block h1 to h2"
  }'
```

**Response:**
```json
{
  "status": "success",
  "intent": {
    "id": 1,
    "type": "block",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02",
    "enabled": true,
    "description": "Block h1 to h2"
  }
}
```

**Test in Mininet:**
```bash
mininet> h1 ping h2 -c 3
# Should FAIL (100% packet loss)
```

### Block h2 → h3
```bash
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "block",
    "src_mac": "00:00:00:00:00:02",
    "dst_mac": "00:00:00:00:00:03",
    "description": "Block h2 to h3"
  }'
```

---

## 4. Enable/Disable Routes

### Disable an Intent (Enable Route)
```bash
curl -X PUT http://localhost:8080/api/intents/1/disable
```

**Test in Mininet:**
```bash
mininet> h1 ping h2 -c 3
# Should NOW WORK! (route enabled)
```

### Enable an Intent (Block Route Again)
```bash
curl -X PUT http://localhost:8080/api/intents/1/enable
```

**Test in Mininet:**
```bash
mininet> h1 ping h2 -c 3
# Should FAIL again (route blocked)
```

---

## 5. Remove Intents Completely

### Delete an Intent
```bash
curl -X DELETE http://localhost:8080/api/intents/1
```

**Response:**
```json
{
  "status": "success",
  "removed": {
    "id": 1,
    "type": "block",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02"
  }
}
```

---

## 6. Prioritize Traffic

### High Priority for h1 → h3
```bash
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "priority",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:03",
    "priority": 100,
    "description": "High priority for h1 to h3"
  }'
```

### Low Priority for h2 → h3
```bash
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "priority",
    "src_mac": "00:00:00:00:00:02",
    "dst_mac": "00:00:00:00:00:03",
    "priority": 5,
    "description": "Low priority for h2 to h3"
  }'
```

**Check flows in Mininet:**
```bash
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
# You'll see different priority values!
```

---

## 7. Redirect Traffic

### Redirect h1 → h2 via port 3
```bash
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "redirect",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02",
    "out_port": 3,
    "description": "Redirect h1 to h2 via port 3"
  }'
```

---

## Complete Testing Workflow

### Step 1: Check initial connectivity
```bash
mininet> pingall
# All should work: h1 -> h2, h1 -> h3, h2 -> h3
```

### Step 2: Block h1 → h2
```bash
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "block",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02"
  }'
```

```bash
mininet> h1 ping h2
# FAILS ✗

mininet> h1 ping h3
# WORKS ✓

mininet> h2 ping h1
# WORKS ✓ (only h1 -> h2 is blocked, not h2 -> h1)
```

### Step 3: View all intents
```bash
curl http://localhost:8080/api/intents
```

### Step 4: Disable the block (enable route)
```bash
curl -X PUT http://localhost:8080/api/intents/1/disable
```

```bash
mininet> h1 ping h2
# WORKS NOW ✓
```

### Step 5: Re-enable the block
```bash
curl -X PUT http://localhost:8080/api/intents/1/enable
```

```bash
mininet> h1 ping h2
# FAILS AGAIN ✗
```

### Step 6: Remove the intent completely
```bash
curl -X DELETE http://localhost:8080/api/intents/1
```

```bash
mininet> h1 ping h2
# WORKS ✓ (no more blocking)
```

### Step 7: Add priorities
```bash
# High priority h1 -> h3
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "priority",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:03",
    "priority": 100
  }'

# Low priority h2 -> h3
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "priority",
    "src_mac": "00:00:00:00:00:02",
    "dst_mac": "00:00:00:00:00:03",
    "priority": 5
  }'
```

```bash
# Generate traffic
mininet> h1 ping h3 -c 5
mininet> h2 ping h3 -c 5

# Check installed flows with priorities
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

## Intent Types Summary

| Type | Description | Required Fields |
|------|-------------|----------------|
| `block` | Drop all packets matching src/dst | `src_mac`, `dst_mac` |
| `redirect` | Forward packets to specific port | `src_mac`, `dst_mac`, `out_port` |
| `priority` | Set flow priority (higher = more important) | `src_mac`, `dst_mac`, `priority` |

---

## Advanced Examples

### Mirror traffic (monitor h1 → h2)
```bash
# First, redirect to monitoring port
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "redirect",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02",
    "out_port": 4,
    "description": "Mirror h1 to h2"
  }'
```

### Block all traffic from h1
```bash
# Block h1 -> h2
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{"type": "block", "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}'

# Block h1 -> h3
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{"type": "block", "src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:03"}'
```

### QoS: Prioritize video traffic over web traffic
```bash
# Video traffic: h1 -> h2 (high priority)
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "priority",
    "src_mac": "00:00:00:00:00:01",
    "dst_mac": "00:00:00:00:00:02",
    "priority": 200,
    "description": "Video streaming priority"
  }'

# Web traffic: h2 -> h3 (normal priority)
curl -X POST http://localhost:8080/api/intents \
  -H "Content-Type: application/json" \
  -d '{
    "type": "priority",
    "src_mac": "00:00:00:00:00:02",
    "dst_mac": "00:00:00:00:00:03",
    "priority": 10,
    "description": "Web browsing priority"
  }'
```

---

## Debugging Commands

### View controller logs
Watch the controller terminal for:
- `PACKET_IN` messages
- `Flow installed` with priority values
- `Intent BLOCK/REDIRECT` messages

### View switch flows
```bash
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

### Clear all flows (reset)
```bash
mininet> sh ovs-ofctl -O OpenFlow13 del-flows s1
```

### View statistics
```bash
curl http://localhost:8080/api/stats
```

---

## Quick Reference

```bash
# View
GET  /api/topology          - Network topology
GET  /api/intents           - All intents
GET  /api/flows/{dpid}      - MAC learning table
GET  /api/stats             - Network statistics

# Create
POST /api/intents           - Add new intent

# Modify
PUT  /api/intents/{id}/enable   - Enable intent
PUT  /api/intents/{id}/disable  - Disable intent

# Delete
DELETE /api/intents/{id}    - Remove intent
```