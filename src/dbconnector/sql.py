"""
Модуль с запросами к базе данных
"""


CREATE_TABLE_SCAN_CONFIGS = '''
CREATE TABLE IF NOT EXISTS scan_configs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    user TEXT NOT NULL,
    secret TEXT NOT NULL,
    description TEXT NOT NULL,
    date TEXT NOT NULL,
    port TEXT NOT NULL,
    report_type TEXT NOT NULL
);
'''

CREATE_TABLE_PROJECT_CONFIGS = '''
CREATE TABLE IF NOT EXISTS project_configs (
    id INTEGER PRIMARY KEY,
    scan_config_name TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    dir_path TEXT NOT NULL,
    description TEXT NOT NULL
);
'''

SELECT_ALL_SCAN_CONFIGS = '''
SELECT id, name, host, user, secret, description, date, port, report_type
FROM scan_configs;
'''

SELECT_SCAN_CONFIGS = '''
SELECT id, name, host, user, secret, description, date, port, report_type
FROM scan_configs
WHERE name='{name}';
'''

SELECT_SCAN_CONFIG_BY_ID = '''
SELECT id, name, host, user, secret, description, date, port, report_type
FROM scan_configs
WHERE id='{id}';
'''

SELECT_PROJECT_CONFIGS = '''
SELECT id, scan_config_name, name, type, dir_path, description
FROM project_configs
WHERE scan_config_name='{scan_config_name}';
'''

INSERT_INTO_SCAN_CONFIGS = '''
INSERT INTO scan_configs
(
    name,
    host,
    user,
    secret,
    description,
    date,
    port,
    report_type
)
VALUES (
    "{name}",
    "{host}",
    "{user}",
    "{secret}",
    "{description}",
    "{date}",
    "{port}",
    "{report_type}"
);
'''

DELETE_SCAN_CONFIG = '''
DELETE FROM scan_configs
WHERE name='{name}';
'''

UPDATE_SCAN_CONFIG = '''
UPDATE scan_configs
SET
    name={name},
    host={host},
    user={user},
    secret={secret},
    description={description},
    date={date},
    port={port},
    report_type={report_type}
WHERE name={name};
'''

UPDATE_SCAN_CONFIG_BY_ID = '''
UPDATE scan_configs
SET
    name={name},
    host={host},
    user={user},
    secret={secret},
    description={description},
    date={date},
    port={port},
    report_type={report_type}
WHERE id={id};
'''

DELETE_SCAN_CONFIG_BY_ID = '''
DELETE FROM scan_configs
WHERE id='{id}';
'''

INSERT_INTO_PROJECT_CONFIGS = '''
INSERT INTO project_configs
(
    scan_config_name,
    name,
    type,
    dir_path,
    description
)
VALUES (
    "{scan_config_name}",
    "{name}",
    "{type}",
    "{dir_path}",
    "{description}"
);
'''
