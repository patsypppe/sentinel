-- The warehouse `warehouse.query` reads.
--
-- It lives in its own schema so the scope allowlist has something real to
-- allow, and so a query reaching outside it is a genuine boundary crossing
-- rather than a naming convention.
--
-- `warehouse_restricted` exists to be DENIED. A tool that can only ever succeed
-- proves nothing about its own access control, so there is a table the analyst
-- principal is not scoped for and a test that confirms the refusal.

CREATE SCHEMA warehouse;
CREATE SCHEMA warehouse_restricted;

CREATE TABLE warehouse.customers (
    customer_id  bigint PRIMARY KEY,
    name         text NOT NULL,
    region       text NOT NULL,
    signed_up_at timestamptz NOT NULL
);

CREATE TABLE warehouse.orders (
    order_id     bigint PRIMARY KEY,
    customer_id  bigint NOT NULL REFERENCES warehouse.customers(customer_id),
    status       text NOT NULL,
    total_cents  bigint NOT NULL,
    placed_at    timestamptz NOT NULL
);

CREATE INDEX orders_customer_idx ON warehouse.orders (customer_id);
CREATE INDEX orders_placed_idx ON warehouse.orders (placed_at);

-- Salary data. Deliberately outside every scope the demo principals hold.
CREATE TABLE warehouse_restricted.payroll (
    employee_id   bigint PRIMARY KEY,
    full_name     text NOT NULL,
    annual_cents  bigint NOT NULL
);

INSERT INTO warehouse.customers (customer_id, name, region, signed_up_at)
SELECT
    i,
    'Customer ' || i,
    (ARRAY['emea', 'amer', 'apac'])[1 + (i % 3)],
    now() - (i || ' days')::interval
FROM generate_series(1, 500) AS i;

-- 5,000 orders: comfortably more than the default row cap, so the handle
-- overflow path is reachable with an ordinary query rather than a contrived one.
INSERT INTO warehouse.orders (order_id, customer_id, status, total_cents, placed_at)
SELECT
    i,
    1 + (i % 500),
    (ARRAY['placed', 'shipped', 'delivered', 'refunded'])[1 + (i % 4)],
    (100 + (i * 37) % 90000),
    now() - (i || ' hours')::interval
FROM generate_series(1, 5000) AS i;

INSERT INTO warehouse_restricted.payroll (employee_id, full_name, annual_cents) VALUES
    (1, 'Should Not Be Readable', 19000000);

-- The application role may read the warehouse schema and NOT the restricted
-- one. This is defence in depth behind the scope allowlist, not a replacement
-- for it: the allowlist gives an actionable error, the grant is what holds if
-- the allowlist is ever wrong.
GRANT USAGE ON SCHEMA warehouse TO broker_app;
GRANT SELECT ON ALL TABLES IN SCHEMA warehouse TO broker_app;
