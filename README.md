# SecLang DB Import

Parse [ModSecurity / seclang](https://github.com/owasp-modsecurity/ModSecurity)
`.conf` files and dump every `SecRule` / `SecAction` directive into a JSON
file suitable for loading into a database (the example here targets
ClickHouse with the `Join` table engine).

## Usage

```sh
uv run python main.py <path> [-o rules.json]
```

## Loading into ClickHouse

Create the target table with the `Join` engine so rules can be looked up by
`id` via `joinGet` or a `LEFT JOIN`:

```sql
CREATE TABLE modsecurity_rules
(
    id UInt64,
    phase String,
    action String,
    severity String,
    version String,
    message String,
    maturity UInt8,
    accuracy UInt8,
    revision String,
    paranoia_level UInt8,
    tags Array(String),
    raw String,
    generated_id String MATERIALIZED lower(HEX(MD5(version || id)))
)
ENGINE = Join(ANY, LEFT, id);
```

Drop the generated `rules.json` into ClickHouse's user files directory
(typically `/var/lib/clickhouse/user_files/`) and import:

```sql
INSERT INTO modsecurity_rules SELECT * FROM file('rules.json');
```
