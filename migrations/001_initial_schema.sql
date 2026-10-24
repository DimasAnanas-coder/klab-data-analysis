CREATE TABLE IF NOT EXISTS products (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vendor TEXT NOT NULL,
    name TEXT NOT NULL,
    CONSTRAINT products_vendor_name_unique UNIQUE (vendor, name)
);

CREATE TABLE IF NOT EXISTS product_versions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_id BIGINT NOT NULL REFERENCES products (id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    CONSTRAINT product_versions_product_version_unique UNIQUE (product_id, version)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_id BIGINT NOT NULL REFERENCES products (id) ON DELETE CASCADE,
    kla_id TEXT NOT NULL,
    description TEXT NOT NULL,
    publish_date DATE NOT NULL,
    start_vuln_version TEXT NOT NULL,
    fixed_version TEXT NOT NULL,
    CONSTRAINT vulnerabilities_record_unique UNIQUE (
        product_id,
        kla_id,
        start_vuln_version,
        fixed_version
    )
);

CREATE INDEX IF NOT EXISTS vulnerabilities_product_id_idx ON vulnerabilities (product_id);
CREATE INDEX IF NOT EXISTS products_name_idx ON products (name);
