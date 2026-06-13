# Subscription Groups and Load Balancing

## Goal
Add subscription groups managed by the admin. Load balance users across subscriptions within a group to avoid overloading individual subscriptions and exceeding traffic limits.

---

## 1. Database Schema Changes

### SubscriptionGroup Table
- `id`: UUID (Primary Key)
- `name`: Text (Unique, nullable=False)
- `created_at`: DateTime (Timezone=True, default=utcnow)

### ProviderSubscription Table Update
- `group_id`: UUID (Foreign Key targeting `subscription_groups.id`, nullable=True)

---

## 2. Pool Generation and Filtering (services/pool.py)

1. **Pool Enrichment**:
   - For every outbound dict in `_build_pool()`, preserve/embed `_sub_id` (string uuid) and `_group_id` (string uuid or `None`) inside the dictionary keys.
   - Example dictionary structure in memory pool:
     ```python
     {
         "tag": "p-0-0",
         "protocol": "vmess",
         "settings": {...},
         "streamSettings": {...},
         "_sub_id": "...",
         "_group_id": "..."
     }
     ```

2. **Selecting Outbounds for Users** (`select_user_outbounds`):
   - Group the pool's outbounds by `_group_id`. If `_group_id` is `None` (ungrouped), treat it as a group of its own using `_sub_id` as the group key.
   - For each group:
     - Get all active subscriptions contributing outbounds to this group.
     - Select ONE subscription within the group deterministically using user token hash:
       `hash(token + group_id) % num_subs_in_group`
     - Only retain outbounds belonging to the selected subscription for this group.
   - Re-flatten all selected outbounds from all groups.
   - Slice the top $K$ (e.g. `settings.outbounds_per_user`) outbounds from this filtered set.

---

## 3. Configuration Generation (services/builder.py)

- Before rendering the final xray JSON configuration helper in `_build_xray_config`, clean up any leading/meta keys (like `_sub_id`, `_group_id`) to ensure standard compliance.

---

## 4. API Endpoints (api/admin.py)

### Subscription Groups CRUD
- `POST /api/admin/subscription-groups` (Create Group)
- `GET /api/admin/subscription-groups` (List Groups)
- `PATCH /api/admin/subscription-groups/{group_id}` (Update Group Name)
- `DELETE /api/admin/subscription-groups/{group_id}` (Delete Group)

### Provider Subscription Updates
- Update request schemas (`ProviderSubCreate`, `ProviderSubUpdate`) and responses to accept/return the `group_id`.

---

## 5. Migration (Alembic)
- Generate a migration file to create `subscription_groups` table and alter `provider_subscriptions` table.
