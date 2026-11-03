CREATE TABLE threats (
    md5 TEXT PRIMARY KEY NOT NULL
        CHECK (length(md5) = 32 AND md5 NOT GLOB '*[^0-9a-f]*'),
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 200),
    description TEXT NOT NULL CHECK (length(description) <= 4000),
    threat_type TEXT NOT NULL
        CHECK (threat_type IN ('unknown', 'trojan', 'ransomware', 'worm', 'spyware', 'adware', 'rootkit', 'other')),
    severity TEXT NOT NULL CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    tags TEXT NOT NULL CHECK (json_valid(tags) AND json_type(tags) = 'array'),
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
