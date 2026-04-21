import argparse
import json
import pathlib
from typing import Iterator, NotRequired, TypedDict

import msc_pyparser

DISRUPTIVE_ACTIONS = {
    "deny",
    "drop",
    "redirect",
    "allow",
    "block",
    "pass",
}

PHASES = {
    1: "request_headers",
    2: "request_body",
    3: "response_headers",
    4: "response_body",
    5: "logging",
}

SEVERITY = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


class Action(TypedDict):
    act_name: str
    lineno: int
    act_quote: str
    act_arg: str
    act_arg_val: str
    act_arg_val_param: str
    act_arg_val_param_val: str


class Variable(TypedDict):
    variable: str
    variable_part: str
    quote_type: str
    negated: bool
    counter: bool


class ConfigLine(TypedDict):
    type: str
    lineno: int
    actions: NotRequired[list[Action]]
    variables: NotRequired[list[Variable]]
    operator: NotRequired[str]
    operator_argument: NotRequired[str]
    operator_negated: NotRequired[bool]
    oplineno: NotRequired[int]
    chained: NotRequired[bool]


class Rule(TypedDict):
    raw: str
    id: int | None
    phase: str | None
    action: str | None
    severity: str | None
    version: str | None
    message: str | None
    tags: list[str]


def get_arg_value(d: dict[int, str], arg: str) -> str:
    return d.get(int(arg), arg) if arg.isdigit() else arg.lower()


def extract_raw(
    config: ConfigLine,
    chain_children: list[ConfigLine],
    source_lines: list[str],
) -> str:
    start = config["lineno"]
    end = start
    for c in (config, *chain_children):
        end = max(end, c.get("lineno", start))
        for a in c.get("actions", []):
            end = max(end, a["lineno"])
    return "\n".join(source_lines[start - 1 : end])


def extract_rule(
    config: ConfigLine,
    source_lines: list[str],
    chain_children: list[ConfigLine],
) -> Rule:
    raw = extract_raw(config, chain_children, source_lines)

    rule: Rule = {
        "raw": raw,
        "id": None,
        "phase": None,
        "action": None,
        "severity": None,
        "version": None,
        "message": None,
        "tags": [],
    }

    for action in config.get("actions", []):
        name = action["act_name"]
        arg = action.get("act_arg", "")

        if name == "id" and arg.isdigit():
            rule["id"] = int(arg)
        elif name == "phase":
            rule["phase"] = get_arg_value(PHASES, arg)
        elif name in DISRUPTIVE_ACTIONS:
            rule["action"] = name
        elif name == "severity":
            rule["severity"] = get_arg_value(SEVERITY, arg)
        elif name == "ver":
            rule["version"] = arg
        elif name == "msg":
            rule["message"] = arg
        elif name == "tag":
            rule["tags"].append(arg)

    return rule


def iter_conf_files(path: pathlib.Path) -> Iterator[pathlib.Path]:
    if path.is_dir():
        yield from sorted(path.glob("*.conf"))
    else:
        yield path


def has_id(config: ConfigLine) -> bool:
    return any(action["act_name"] == "id" for action in config.get("actions", []))


def iter_rule_groups(
    configlines: list[ConfigLine],
) -> Iterator[tuple[ConfigLine, list[ConfigLine]]]:
    i = 0
    while i < len(configlines):
        config = configlines[i]
        i += 1
        if config.get("type") not in ("SecRule", "SecAction") or not has_id(config):
            continue

        chain_children: list[ConfigLine] = []
        while i < len(configlines):
            nxt = configlines[i]
            if nxt.get("type") != "SecRule" or has_id(nxt):
                break
            chain_children.append(nxt)
            i += 1

        yield config, chain_children


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dump seclang SecRule/SecAction entries from PATH (file or directory) as JSON.",
    )
    parser.add_argument(
        "path",
        type=pathlib.Path,
        help="Path to a seclang .conf file or a directory of .conf files.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("rules.json"),
        help="Output file (default: %(default)s).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    path: pathlib.Path = args.path
    output: pathlib.Path = args.output

    if not path.exists():
        raise SystemExit(f"error: path does not exist: {path}")

    rules = []
    for file in iter_conf_files(path):
        text = file.read_text()
        source_lines = text.splitlines()

        parser = msc_pyparser.MSCParser()
        parser.parser.parse(text)

        for config, chain_children in iter_rule_groups(parser.configlines):
            rules.append(extract_rule(config, source_lines, chain_children))

    output.write_text(json.dumps(rules, indent=2))

    print(f"Wrote {len(rules)} rules to {output}")


if __name__ == "__main__":
    main()
