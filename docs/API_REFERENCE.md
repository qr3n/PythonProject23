# VPN Subscription Manager: API Reference

This document provides a comprehensive guide to the VPN Subscription Manager API. It is designed to be highly detailed to assist both human developers and LLMs in building frontends or integrating with the service.

---

## 1. General Information

*   **Base URL:** `http://<your-server-ip>:8000`
*   **Content-Type:** `application/json`
*   **Authentication:** 
    *   **Admin API:** Requires a Bearer token in the header.
        *   `Authorization: Bearer <ADMIN_KEY>` (Value is defined in the `.env` file as `ADMIN_KEY`).
    *   **Client API:** No header required; authorization is handled via the unique user token in the URL path.

---

## 2. Admin API Endpoints

All endpoints in this section require the `Authorization: Bearer` header.

### 2.1 Provider Subscriptions
Manage external VPN subscription links.

#### **GET** `/api/admin/provider-subs`
Retrieve a list of all configured provider subscriptions.

*   **Success Response (200 OK):**
    ```json
    [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "alias": "Main HK Provider",
        "url": "https://fast-node.com/sub/123456",
        "expires_at": "2026-12-31T23:59:59Z",
        "traffic_total_gb": 1000.0,
        "traffic_used_gb": 450.5,
        "last_fetched_at": "2026-06-13T10:00:00Z",
        "group_id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
        "is_active": true,
        "created_at": "2026-06-01T12:00:00Z",
        "outbound_count": 42
      }
    ]
    ```

#### **POST** `/api/admin/provider-subs`
Add a new provider subscription.

*   **Request Body:**
    ```json
    {
      "alias": "Premium US Nodes",
      "url": "https://premium-vpn.net/export?type=v2ray",
      "group_id": "optional-group-uuid",
      "auto_refresh": true
    }
    ```
*   **Success Response (201 Created):**
    ```json
    {
      "id": "8e9f2c3a-...",
      "alias": "Premium US Nodes",
      "warning": null,
      "outbound_count": 15
    }
    ```

#### **POST** `/api/admin/provider-subs/{sub_id}/refresh`
Manually trigger a fetch of the latest nodes from the provider URL.

*   **Success Response (200 OK):**
    ```json
    {
      "outbound_count": 24,
      "traffic_used_gb": 12.5,
      "traffic_total_gb": 500.0,
      "expires_at": "2027-01-01T00:00:00Z",
      "message": "Refreshed 24 outbounds"
    }
    ```

---

### 2.2 Subscription Groups
Group providers for deterministic load balancing.

#### **POST** `/api/admin/subscription-groups`
Create a new group.

*   **Request Body:**
    ```json
    {
      "name": "High-Speed-Cluster"
    }
    ```
*   **Success Response (201 Created):**
    ```json
    {
      "id": "a1b2c3d4-...",
      "name": "High-Speed-Cluster",
      "created_at": "2026-06-13T15:00:00Z"
    }
    ```

---

### 2.3 User Management
Manage clients and their access tokens.

#### **POST** `/api/admin/users`
Create a new VPN user.

*   **Request Body:**
    ```json
    {
      "name": "John Doe",
      "subscription_expires_at": "2026-07-13T00:00:00Z",
      "is_active": true
    }
    ```
*   **Success Response (201 Created):**
    ```json
    {
      "id": "f47ac10b-...",
      "name": "John Doe",
      "token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
      "sub_url": "http://your-server.com/sub/a1b2c3d4...",
      "check_url": "http://your-server.com/check/a1b2c3d4...",
      "is_active": true,
      "subscription_expires_at": "2026-07-13T00:00:00Z"
    }
    ```

#### **POST** `/api/admin/users/{user_id}/reset-token`
Invalidate the old token and generate a new one.

*   **Success Response (200 OK):**
    ```json
    {
      "token": "new-64-char-hex-string",
      "sub_url": "http://your-server.com/sub/new-token",
      "check_url": "http://your-server.com/check/new-token"
    }
    ```

---

### 2.4 Address Filter Rules
Control which proxy server addresses are allowed in the pool.

#### **POST** `/api/admin/filter-rules`
Add a block or allow rule.

*   **Request Body:**
    ```json
    {
      "description": "Block Russian IPs",
      "pattern": "95.161.0.0/16",
      "action": "block",
      "is_active": true
    }
    ```
    *Patterns can be:*
    - **Glob:** `*.ru`, `*google.com`
    - **CIDR:** `192.168.1.0/24`
    - **Regex:** `/^cdn\d+\.example\.com$/`

---

## 3. Client API Endpoints

Public endpoints for VPN clients (v2rayNG, Stash, Shadowrocket, etc.) and Xray observatories.

### 3.1 Get Subscription Config
**GET** `/sub/{token}`

Returns a complete Xray JSON configuration.

*   **Success Response (200 OK):**
    ```json
    {
      "log": { "loglevel": "warning" },
      "outbounds": [
        { "tag": "p-0-1", "protocol": "vless", "settings": { ... }, "streamSettings": { ... } },
        { "tag": "block", "protocol": "blackhole" }
      ],
      "routing": {
        "balancers": [{ "tag": "proxy-balancer", "selector": ["p-"], "strategy": { "type": "leastPing" } }]
      },
      "burstObservatory": {
        "probeUrl": "http://your-server.com/check/your-token",
        "probeInterval": "30s"
      }
    }
    ```

### 3.2 Connectivity Check
**GET** `/check/{token}`

Used by Xray's `burstObservatory` as a probe.

*   **Response (200 OK):** `{"status": "ok"}` (User is active)
*   **Response (503 Service Unavailable):** `{"detail": "Subscription inactive"}` (User expired or disabled)

---

## 4. Key Logic & "Superpowers"

1.  **Pool Versioning:** Every time you add/edit a provider or rule, the `pool:version` increments. This instantly invalidates all cached user configurations, ensuring clients get updated nodes without waiting for TTL.
2.  **Deterministic Load Balancing:** If two providers are in the same Group, the system uses `MD5(token + group_id)` to pick one. This means a specific user always gets the same provider from that group, but across all users, the load is split 50/50 between the two providers.
3.  **DNS Filtering:** When you block an IP like `1.2.3.4`, the system also resolves all provider domains. If `proxy.example.com` resolves to `1.2.3.4`, that node will be automatically blocked.

---

## 5. Implementation Tips for Frontend (LLM/Human)

*   **Polling:** Use a short poll or manual refresh for the "Provider Refresh" status, as it might take a few seconds to fetch external data.
*   **Copy to Clipboard:** Provide a prominent "Copy Link" button for the User `sub_url`.
*   **Validation:** Ensure `pattern` in filter rules is validated against CIDR/Regex/Glob standards on the frontend for better UX.
*   **Dashboard Idea:** Show a summary of `traffic_used_gb` vs `traffic_total_gb` across all providers to visualize overall bandwidth health.
