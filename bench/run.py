# /// script
# requires-python = ">=3.11"
# dependencies = ["tiktoken==0.12.0"]
# ///
"""What realistic mail tasks cost an agent using kaist-mail.

Each workflow is a scripted agent: it runs the release binary against the
synthetic mailbox in dooray.py, decides its next command from the output it
saw, and is checked against the task's known answer. Cost is what the agent
pays: commands it writes, tokens it reads (stdout and stderr), and what the
binary moved over HTTP.

    cargo build --release --locked
    uv run bench/run.py [--latency-ms 300] [--only TASK]
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import tiktoken

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dooray

ROOT = Path(__file__).resolve().parent.parent
TOKENIZER = "o200k_base"
ENCODING = tiktoken.get_encoding(TOKENIZER)
AUTOMATED = re.compile(r"no-?reply|notifications|news|alerts", re.IGNORECASE)


@dataclass
class Step:
    command: str
    requests: int
    upstream: int
    output: int
    tokens: int
    seconds: float


@dataclass
class Agent:
    binary: Path
    server: dooray.Server
    home: Path
    out: Path
    steps: list[Step] = field(default_factory=list)

    def run(self, *args: str) -> str:
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "XDG_STATE_HOME": str(self.home / "state"),
            "XDG_CONFIG_HOME": str(self.home / "config"),
            "KAIST_MAIL_BASE_URL": self.server.url,
            "KAIST_MAIL_SSO_URL": self.server.url + "/",
        }
        logged = len(self.server.log)
        start = time.perf_counter()
        done = subprocess.run(
            [self.binary, *args], capture_output=True, env=env, check=False
        )
        seconds = time.perf_counter() - start
        exchanges = self.server.log[logged:]
        output = done.stdout + done.stderr
        self.steps.append(
            Step(
                shlex.join(["kaist-mail", *args]),
                len(exchanges),
                sum(e.received + e.sent for e in exchanges),
                len(output),
                len(ENCODING.encode(output.decode())),
                seconds,
            )
        )
        if done.returncode != 0:
            raise RuntimeError(f"{shlex.join(args)} failed: {output.decode()}")
        return done.stdout.decode()

    def json(self, *args: str) -> dooray.Json:
        return json.loads(self.run("--json", *args))

    def rows(self, *args: str) -> list[dooray.Json]:
        """Every row of a list or search, following next_cursor."""
        rows, cursor = [], []
        while True:
            page = self.json(*args, *cursor)
            rows += page["data"]
            if "next_cursor" not in page["meta"]:
                return rows
            cursor = ["--cursor", page["meta"]["next_cursor"]]

    def read(self, id: str, *args: str) -> dooray.Json:
        return self.json("read", id, *args)["data"]

    def read_all(self, id: str) -> str:
        """The whole body, window by window at the default size."""
        text, offset = "", []
        while True:
            body = self.read(id, *offset)["body"]
            text += body["text"]
            if "next_offset" not in body:
                return text
            offset = ["--offset", str(body["next_offset"])]


def first(
    agent: Agent,
    rows: list[dooray.Json],
    wanted: Callable[[str], str | None],
    *args: str,
) -> str | None:
    """Reads `rows` in order until `wanted` finds the answer in a body."""
    for row in rows:
        if (answer := wanted(agent.read(row["id"], *args)["body"]["text"])) is not None:
            return answer
    return None


def orientation_room(text: str) -> str | None:
    found = re.search(r"Location: (.+)", text)
    return found[1].strip() if found and "Spring 2024 semester" in text else None


def location(text: str) -> str | None:
    found = re.search(r"Location: (.+)", text)
    return found[1].strip() if found else None


def classroom(text: str) -> str | None:
    found = re.search(r"변경 강의실: (.+)", text)
    return found[1].strip() if found and "CS492" in text else None


def enrollment(text: str) -> str | None:
    found = re.search(r"석박사통합과정의 재학연한은 (\d+년)", text)
    return found[1] if found else None


def sent_in(row: dooray.Json, prefix: str) -> bool:
    return row["at"].startswith(prefix)


ORIENTATION = "Exchange Student Orientation"
Workflow = Callable[[Agent], object]


def t1_subject(*search_args: str) -> Workflow:
    def run(agent: Agent) -> object:
        rows = agent.rows("search", "--subject", ORIENTATION, *search_args)
        return first(agent, [r for r in rows if sent_in(r, "2024-0")], orientation_room)

    return run


def t1_dated(agent: Agent) -> object:
    rows = agent.rows(
        "search",
        "--subject",
        ORIENTATION,
        "--since",
        "2024-01-01",
        "--before",
        "2024-07-01",
    )
    return first(agent, rows[:1], orientation_room)


def t1_body(*read_args: str) -> Workflow:
    def run(agent: Agent) -> object:
        rows = agent.rows("search", "--subject", ORIENTATION, "--body", "Spring 2024")
        return first(agent, rows[:1], location, *read_args)

    return run


def t1_naive(agent: Agent) -> object:
    return first(agent, agent.rows("search", "orientation"), orientation_room)


ROOM_CHANGE = "강의실 변경"


def t2_subject(*search_args: str, read: tuple[str, ...] = ()) -> Workflow:
    def run(agent: Agent) -> object:
        search = ["search", "--from", "학사팀", "--subject", ROOM_CHANGE, *search_args]
        return first(agent, agent.rows(*search), classroom, *read)

    return run


def t2_body(agent: Agent) -> object:
    rows = agent.rows("search", "--body", "CS492")
    return first(agent, [r for r in rows if ROOM_CHANGE in r["subject"]], classroom)


def t2_body_subject(*args: str) -> Workflow:
    def run(agent: Agent) -> object:
        return first(
            agent,
            agent.rows("search", "--subject", ROOM_CHANGE, "--body", "CS492")[:1],
            classroom,
            *args,
        )

    return run


def downloaded(files: list[dooray.Json]) -> object:
    for file in files:
        path = Path(file["path"])
        if path.name == "연구실안전교육_이수증_2023.pdf":
            return path.name, path.stat().st_size
    return None


def t3_part(term: str, *read_args: str) -> Workflow:
    def run(agent: Agent) -> object:
        rows = agent.rows("search", "--file", term)
        row = next(r for r in rows if sent_in(r, "2023"))
        attachments = agent.read(row["id"], *read_args)["attachments"]
        part = next(a["part"] for a in attachments if "이수증" in a["name"])
        out = ["--part", str(part), "--out", str(agent.out)]
        return downloaded(agent.json("download", row["id"], *out)["data"]["files"])

    return run


def t3_download_all(agent: Agent) -> object:
    row = agent.rows("search", "--file", "이수증_2023")[0]
    out = ["--out", str(agent.out)]
    return downloaded(agent.json("download", row["id"], *out)["data"]["files"])


TRIAGE = 50


def requests_in(text: str) -> bool:
    return dooray.REQUEST.search(text) is not None


def t4_triage(limit: str, preview: bool) -> Workflow:
    """Pages the newest unread, reading as it goes. Without previews it reads
    every message a person or office sent; with them it reads only a person's
    or office's message whose cut preview does not already show a request."""

    def run(agent: Agent) -> object:
        found: set[str] = set()
        seen, cursor = 0, []
        while seen < TRIAGE:
            page = agent.json(
                "list",
                "--unread",
                "--limit",
                limit,
                *(["--preview"] if preview else []),
                *cursor,
            )
            for row in page["data"][: TRIAGE - seen]:
                seen += 1
                if AUTOMATED.search(row["from"]):
                    continue
                shown = row.get("preview", "")
                if preview and (requests_in(shown) or len(shown) < 190):
                    if requests_in(shown):
                        found.add(row["id"])
                    continue
                if requests_in(agent.read(row["id"])["body"]["text"]):
                    found.add(row["id"])
            cursor = ["--cursor", page["meta"]["next_cursor"]]
        return found

    return run


REGULATION = "학위과정 운영 규정 개정"


def t5_paged(agent: Agent) -> object:
    row = agent.rows("search", "--subject", REGULATION)[0]
    return enrollment(agent.read_all(row["id"]))


def t5_find(*args: str) -> Workflow:
    def run(agent: Agent) -> object:
        row = agent.rows("search", "--subject", REGULATION, "--body", "재학연한")[0]
        return enrollment(
            agent.read(row["id"], "--find", "재학연한", *args)["body"]["text"]
        )

    return run


def t5_whole(agent: Agent) -> object:
    row = agent.rows("search", "--subject", REGULATION)[0]
    return enrollment(agent.read(row["id"], "--max-chars", "100000")["body"]["text"])


ACADEMIC = ["search", "--from", "academic@kaist.ac.kr", "--unread", "--folder", "inbox"]


def t6_count(*args: str) -> Workflow:
    return lambda agent: agent.json(*ACADEMIC, *args)["meta"]["total"]


def t6_human(agent: Agent) -> object:
    found = re.search(r" of (\d+) shown", agent.run(*ACADEMIC, "--limit", "1"))
    return int(found[1]) if found else None


@dataclass
class Task:
    name: str
    question: str
    answer: Callable[[dooray.Truth], object]
    workflows: dict[str, Workflow]


TASKS = [
    Task(
        "T1 older notice, body fact",
        "Where was the Spring 2024 exchange-student orientation held? (semester only in body)",
        lambda t: t.orientation_room,
        {
            "subject search, pick 2024 rows, read": t1_subject(),
            "same, --limit 50": t1_subject("--limit", "50"),
            "same, --preview": t1_subject("--preview"),
            "subject + --since/--before, read 1": t1_dated,
            "subject + --body 'Spring 2024', read 1": t1_body(),
            "same, read --find 'Spring 2024' --max-chars 300": t1_body(
                "--find", "Spring 2024", "--max-chars", "300"
            ),
            "same, read --find Location --max-chars 300": t1_body(
                "--find", "Location", "--max-chars", "300"
            ),
            "all-field 'orientation', read in order": t1_naive,
        },
    ),
    Task(
        "T2 body-only detail",
        "Which room does CS492 use after its latest room change? (course only in body)",
        lambda t: t.classroom,
        {
            "--from --subject, read in order, limit 20": t2_subject(),
            "same, --limit 50": t2_subject("--limit", "50"),
            "same, --limit 100": t2_subject("--limit", "100"),
            "same, --preview": t2_subject("--preview"),
            "same, read --find CS492 --max-chars 300 in order": t2_subject(
                read=("--find", "CS492", "--max-chars", "300")
            ),
            "--body CS492, read room-change rows": t2_body,
            "--subject + --body CS492, read 1": t2_body_subject(),
            "same, read --find CS492 --max-chars 300": t2_body_subject(
                "--find", "CS492", "--max-chars", "300"
            ),
        },
    ),
    Task(
        "T3 named attachment",
        "Save 연구실안전교육_이수증_2023.pdf from a 2023 message",
        lambda t: t.certificate,
        {
            "--file 이수증, read 2023 row, download --part": t3_part("이수증"),
            "--file 이수증_2023, download all": t3_download_all,
            "--file 이수증_2023, read --max-chars 1, download --part": t3_part(
                "이수증_2023", "--max-chars", "1"
            ),
        },
    ),
    Task(
        "T4 unread triage",
        f"Which of the {TRIAGE} newest unread messages ask me to do something?",
        lambda t: t.triage_ids,
        {
            f"list --unread --limit {limit}{' --preview' if preview else ''}, read as needed": t4_triage(
                limit, preview
            )
            for preview in (False, True)
            for limit in ("20", "50", "100")
        },
    ),
    Task(
        "T5 fact near the end of a long body",
        "What is the 2026 regulation's 재학연한 for 석박사통합과정?",
        lambda t: t.enrollment_years,
        {
            "search, read 4000-char windows": t5_paged,
            "search, read --max-chars 100000": t5_whole,
            "search --body 재학연한, read --find 재학연한": t5_find(),
            "same, --max-chars 400": t5_find("--max-chars", "400"),
        },
    ),
    Task(
        "T6 count",
        "How many unread inbox messages are from 학사팀?",
        lambda t: t.academic_unread,
        {
            "search --unread (limit 20), meta.total": t6_count(),
            "same, --limit 1": t6_count("--limit", "1"),
            "same, --limit 1, human output": t6_human,
        },
    ),
]


@dataclass
class Result:
    task: str
    workflow: str
    correct: bool
    steps: list[Step]
    latency_seconds: float | None


def measure(
    binary: Path, workflow: Workflow, answer: object, latency: float
) -> tuple[bool, list[Step]]:
    mails, _ = dooray.generate()
    server = dooray.Server(dooray.Mailbox(mails), latency)
    with tempfile.TemporaryDirectory() as home:
        state = Path(home, "state/kaist-mail")
        state.mkdir(parents=True)
        session = {
            "version": 1,
            "origin": server.url,
            "created_at": 1,
            "cookies": [{"name": "SESSION", "value": "synthetic"}],
        }
        (state / "session.json").write_text(json.dumps(session))
        out = Path(home, "out")
        out.mkdir()
        agent = Agent(binary, server, Path(home), out)
        got = workflow(agent)
    server.http.shutdown()
    return got == answer, agent.steps


def help_cost(binary: Path) -> list[tuple[str, int, int]]:
    rows: list[tuple[str, int, int]] = []
    for args in (
        ["--help"],
        ["list", "--help"],
        ["search", "--help"],
        ["read", "--help"],
        ["download", "--help"],
    ):
        text = subprocess.run([binary, *args], capture_output=True, check=True).stdout
        rows.append(
            (
                shlex.join(["kaist-mail", *args]),
                len(text),
                len(ENCODING.encode(text.decode())),
            )
        )
    return rows


def table(results: list[Result], latency_ms: int) -> str:
    lines = [
        f"Tokens: tiktoken {TOKENIZER} over the complete stdout+stderr of every command (cmd tok: the command lines the agent writes).",
        "Upstream: HTTP request+response bytes on the loopback (kaist-mail sends no Accept-Encoding, so bodies are uncompressed).",
        f"Time: local wall time of all commands; 'at {latency_ms} ms' adds that fixed delay to every HTTP response in a second run.",
        "",
        f"| task | workflow | ok | cmds | reqs | upstream KB | out bytes | out tok | cmd tok | local s | at {latency_ms} ms s |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        s = r.steps
        cmd_tokens = sum(len(ENCODING.encode(step.command)) for step in s)
        late = f"{r.latency_seconds:.2f}" if r.latency_seconds is not None else "-"
        lines.append(
            f"| {r.task} | {r.workflow} | {'yes' if r.correct else 'NO'} | {len(s)} | {sum(x.requests for x in s)} | "
            f"{sum(x.upstream for x in s) / 1000:.0f} | {sum(x.output for x in s):,} | {sum(x.tokens for x in s):,} | "
            f"{cmd_tokens} | {sum(x.seconds for x in s):.2f} | {late} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "target/release/kaist-mail"
    )
    parser.add_argument("--latency-ms", type=int, default=300)
    parser.add_argument(
        "--only", help="run tasks whose name starts with this, such as T4"
    )
    parser.add_argument(
        "--steps", action="store_true", help="also print every command with its cost"
    )
    args = parser.parse_args()
    _, truth = dooray.generate()
    results: list[Result] = []
    for task in TASKS:
        if args.only and not task.name.startswith(args.only):
            continue
        for name, workflow in task.workflows.items():
            correct, steps = measure(args.binary, workflow, task.answer(truth), 0.0)
            late = None
            if args.latency_ms:
                _, slow = measure(
                    args.binary, workflow, task.answer(truth), args.latency_ms / 1000
                )
                late = sum(step.seconds for step in slow)
            results.append(Result(task.name, name, correct, steps, late))
            if args.steps:
                for step in steps:
                    print(
                        f"  {step.tokens:>6} tok {step.requests} req  {step.command}",
                        file=sys.stderr,
                    )
    for task in TASKS:
        print(f"- {task.name}: {task.question}")
    print()
    print(table(results, args.latency_ms))
    print("\n| help page | bytes | tokens |\n|---|---|---|")
    for command, size, tokens in help_cost(args.binary):
        print(f"| `{command}` | {size:,} | {tokens:,} |")


if __name__ == "__main__":
    main()
