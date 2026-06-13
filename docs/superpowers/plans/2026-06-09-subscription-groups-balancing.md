# Subscription Groups and Load Balancing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow admins to manage subscription groups and deterministically load-balance user configs to choose no more than one subscription from each group, balancing the overall load.

**Architecture:** 
1. Introduce a new `SubscriptionGroup` DB model and a nullable `group_id` foreign key on `ProviderSubscription`.
2. Generate an Alembic migration for the schema changes.
3. Enhance the outbound pool build process (`_build_pool`) to embed `_sub_id` and `_group_id` metadata.
4. Implement load balancing logic inside `select_user_outbounds` based on group-wise deterministic user token hashing.
5. Filter out metadata keys from final configs in `_build_xray_config`.
6. Add complete CRUD FastAPI routes for subscription-groups and adjust provider-sub routes.

**Tech Stack:** FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis, Pydantic, Pytest.

---

### Task 1: Database Schema and Models

**Files:**
- Modify: `app/db/models.py`
- Test: Add a new unit test for database schema sanity.

- [ ] **Step 1: Update app/db/models.py to define SubscriptionGroup and add group_id to ProviderSubscription**

Modify: `app/db/models.py`
```python
# Add ForeignKey and relationship imports if missing:
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

# Add SubscriptionGroup definition:
class SubscriptionGroup(Base):
    __tablename__ = "subscription_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    subscriptions: Mapped[list["ProviderSubscription"]] = relationship(
        "ProviderSubscription", back_populates="group", cascade="all, delete-orphan"
    )

# Update ProviderSubscription definition:
class ProviderSubscription(Base):
    # ... existing fields ...
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subscription_groups.id", ondelete="SET NULL"), nullable=True
    )
    group: Mapped[SubscriptionGroup | None] = relationship(
        "SubscriptionGroup", back_populates="subscriptions"
    )
```

- [ ] **Step 2: Generate Alembic migration file**

Run: `pytest` or `alembic` commands to generate the migration. Since it's a local database name issue, run offline generation or manual migration scripts.
Run: `.venv/bin/alembic revision -m "add_subscription_groups"`

- [ ] **Step 3: Implement the migration steps**

Write appropriate upgrade/downgrade code in the generated migration file or `alembic/versions/XXXX_add_subscription_groups.py`.
```python
def upgrade() -> None:
    op.create_table(
        'subscription_groups',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.add_column('provider_subscriptions', sa.Column('group_id', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_provider_subscriptions_group_id_subscription_groups',
        'provider_subscriptions', 'subscription_groups',
        ['group_id'], ['id'], ondelete='SET NULL'
    )

def downgrade() -> None:
    op.drop_constraint('fk_provider_subscriptions_group_id_subscription_groups', 'provider_subscriptions', type_='foreignkey')
    op.drop_column('provider_subscriptions', 'group_id')
    op.drop_table('subscription_groups')
```

- [ ] **Step 4: Commit**

```bash
git add app/db/models.py alembic/versions/*
git commit -m "db: add subscription_groups table and group_id to provider_subscriptions"
```

---

### Task 2: Pydantic Schemas for Subscription Groups

**Files:**
- Create: `app/schemas/subscription_group.py`
- Modify: `app/schemas/provider.py`
- Modify: `app/schemas/__init__.py`

- [ ] **Step 1: Create subscription group schemas**

Create: `app/schemas/subscription_group.py`
```python
import uuid
from datetime import datetime
from pydantic import BaseModel

class SubscriptionGroupCreate(BaseModel):
    name: str

class SubscriptionGroupResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}
```

- [ ] **Step 2: Update provider schemas with group_id**

Modify: `app/schemas/provider.py`
```python
# Add group_id to ProviderSubCreate, ProviderSubUpdate, and ProviderSubResponse:
class ProviderSubCreate(BaseModel):
    alias: str = ""
    url: str
    expires_at: datetime | None = None
    traffic_total_gb: float | None = None
    group_id: uuid.UUID | None = None
    auto_refresh: bool = True

class ProviderSubUpdate(BaseModel):
    alias: str | None = None
    url: str | None = None
    expires_at: datetime | None = None
    traffic_total_gb: float | None = None
    traffic_used_gb: float | None = None
    group_id: uuid.UUID | None = None
    is_active: bool | None = None

class ProviderSubResponse(BaseModel):
    id: uuid.UUID
    alias: str
    url: str
    expires_at: datetime | None
    traffic_total_gb: float | None
    traffic_used_gb: float | None
    last_fetched_at: datetime | None
    group_id: uuid.UUID | None = None
    is_active: bool
    created_at: datetime
    outbound_count: int = 0
```

- [ ] **Step 3: Update app/schemas/__init__.py**

Export any new schemas if they are list exported there.

- [ ] **Step 4: Commit**

```bash
git add app/schemas/
git commit -m "schemas: add subscription group schemas and update provider sub schemas with group_id"
```

---

### Task 3: Load Balancing Core Logic

**Files:**
- Modify: `app/services/pool.py`
- Modify: `app/services/builder.py`

- [ ] **Step 1: Enrich pool with sub_id and group_id metadata**

Modify: `app/services/pool.py:62-116`
```python
def _build_pool(subs: list[ProviderSubscription]) -> list[dict]:
    # ... scoring and filtering ...
    tagged_lists: list[list[dict]] = []
    for sub_idx, (score, sub) in enumerate(scored):
        outbounds = sub.outbounds_json or []
        tagged = []
        for ob_idx, ob in enumerate(outbounds):
            ob_copy = dict(ob)
            ob_copy["tag"] = f"p-{sub_idx}-{ob_idx}"
            # Embed metadata
            ob_copy["_sub_id"] = str(sub.id)
            ob_copy["_group_id"] = str(sub.group_id) if sub.group_id else None
            tagged.append(ob_copy)
        tagged_lists.append(tagged)
        # ... interleave and return ...
```

- [ ] **Step 2: Update select_user_outbounds to balance across sub groups**

Modify: `app/services/pool.py:123-141`
```python
import hashlib

def select_user_outbounds(pool: list[dict], token: str) -> list[dict]:
    n = len(pool)
    if n == 0:
        return []

    # 1. Group outbounds by group_id (if None, use sub_id as its own unique group)
    groups: dict[str, list[dict]] = {}
    for ob in pool:
        grp_key = ob.get("_group_id") or ob.get("_sub_id")
        if grp_key:
            groups.setdefault(grp_key, []).append(ob)

    # 2. For each group, determine which subscriptions are available
    # and deterministically pick exactly ONE subscription per group for this user token.
    selected_outbounds: list[dict] = []
    for grp_key, grp_obs in groups.items():
        # Find all distinct sub_ids in this group
        sub_ids = sorted(list(set(ob["_sub_id"] for ob in grp_obs)))
        if not sub_ids:
            continue
        # Deterministically select one sub_id using md5 hash
        h = hashlib.md5(f"{token}:{grp_key}".encode()).hexdigest()
        idx = int(h, 16) % len(sub_ids)
        chosen_sub_id = sub_ids[idx]
        
        # Only retain outbounds of the chosen subscription
        selected_outbounds.extend(ob for ob in grp_obs if ob["_sub_id"] == chosen_sub_id)

    # 3. Interleave or slice from the selected filtered set
    if not selected_outbounds:
        return []

    # Get user offset based on token and slice K outbounds
    k = min(settings.outbounds_per_user, len(selected_outbounds))
    offset = int(token[:8], 16) % len(selected_outbounds)
    return [selected_outbounds[(offset + i) % len(selected_outbounds)] for i in range(k)]
```

- [ ] **Step 3: Cleanup metadata keys in builder before building xray config**

Modify: `app/services/builder.py:40-120`
```python
def _build_xray_config(
    user: User,
    outbounds: list[dict],
    check_url: str,
) -> dict:
    # Clean up metakeys e.g. _sub_id, _group_id from config
    cleaned_outbounds = []
    for ob in outbounds:
        ob_copy = dict(ob)
        ob_copy.pop("_sub_id", None)
        ob_copy.pop("_group_id", None)
        cleaned_outbounds.append(ob_copy)

    # Use cleaned_outbounds to build the final config dict
    proxy_tags = [ob.get("tag", f"p-{i}") for i, ob in enumerate(cleaned_outbounds)]
    # ... rest of xray config template setup ...
```

- [ ] **Step 4: Commit**

```bash
git add app/services/pool.py app/services/builder.py
git commit -m "feat: select at most one sub per group deteministically using token hash"
```

---

### Task 4: API Endpoints Implementation

**Files:**
- Modify: `app/api/admin.py`

- [ ] **Step 1: Add Subscription Groups CRUD routes**

Modify: `app/api/admin.py` to add new routes.
```python
from app.db.models import SubscriptionGroup
from app.schemas.subscription_group import SubscriptionGroupCreate, SubscriptionGroupResponse

# CRUD routes...
@router.post("/subscription-groups", response_model=SubscriptionGroupResponse, status_code=201)
async def create_subscription_group(body: SubscriptionGroupCreate, _: AdminDep, db: DbDep):
    group = SubscriptionGroup(name=body.name)
    db.add(group)
    await db.flush()
    await db.refresh(group)
    return group

@router.get("/subscription-groups", response_model=list[SubscriptionGroupResponse])
async def list_subscription_groups(_: AdminDep, db: DbDep):
    result = await db.execute(select(SubscriptionGroup).order_by(SubscriptionGroup.created_at.desc()))
    return result.scalars().all()

@router.patch("/subscription-groups/{group_id}", response_model=SubscriptionGroupResponse)
async def update_subscription_group(group_id: uuid.UUID, body: SubscriptionGroupCreate, _: AdminDep, db: DbDep):
    result = await db.execute(select(SubscriptionGroup).where(SubscriptionGroup.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Subscription group not found")
    group.name = body.name
    await db.flush()
    await db.refresh(group)
    return group

@router.delete("/subscription-groups/{group_id}")
async def delete_subscription_group(group_id: uuid.UUID, _: AdminDep, db: DbDep, redis: RedisDep):
    result = await db.execute(select(SubscriptionGroup).where(SubscriptionGroup.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Subscription group not found")
    await db.delete(group)
    await db.flush()
    await increment_pool_version(redis)
    return {"deleted": True}
```

- [ ] **Step 2: Update Provider Sub CRUD routes to handle group_id**

Modify: `app/api/admin.py` inside `create_provider_sub`, `update_provider_sub`, and `_sub_response` helper:
```python
# In create_provider_sub:
sub = ProviderSubscription(
    alias=body.alias,
    url=body.url,
    expires_at=body.expires_at,
    traffic_total_gb=body.traffic_total_gb,
    group_id=body.group_id, # Link group
)

# In update_provider_sub: Update loops through body.model_dump (make sure group_id is handled)

# In helper _sub_response:
def _sub_response(sub: ProviderSubscription) -> ProviderSubResponse:
    return ProviderSubResponse(
        # ... existing ...
        group_id=sub.group_id,
        # ...
    )
```

- [ ] **Step 3: Commit**

```bash
git add app/api/admin.py
git commit -m "api: implement subscription group CRUD and link group_id to provider subscriptions"
```

---

### Task 5: Testing & Verification

- [ ] **Step 1: Write integration tests for group load balancing**

Create `tests/test_balancing.py` to assert that:
1. When two subscriptions belong to the same group, a user gets outbounds from only one of them.
2. Changes to group configuration result in correct pool balance.

```python
import pytest
from app.services.pool import _build_pool, select_user_outbounds
# Test logic ...
```

- [ ] **Step 2: Run verification tests**

Run: `pytest`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: add load balancing test suite"
```
