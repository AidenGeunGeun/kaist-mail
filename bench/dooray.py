"""A synthetic Dooray mailbox at a real account's scale, and a loopback server
that answers the endpoints kaist-mail calls the way docs/PROTOCOL.md says
Dooray does. Response items are the test fixtures' items with the synthetic
values put in, so their byte sizes match Dooray's."""

import copy
import hashlib
import html
import io
import json
import random
import re
import threading
import time
from collections.abc import Buffer
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, override
from urllib.parse import parse_qs, urlsplit

Json = dict[str, Any]
KST = timezone(timedelta(hours=9))
FIXTURES = Path(__file__).resolve().parent.parent / "tests/fixtures"
ME = ("홍길동", "gildong@kaist.ac.kr")
INBOX_TOTAL = 8343
INBOX_UNREAD = 2785
START = datetime(2022, 3, 1, tzinfo=KST)
NOW = datetime(2026, 11, 12, 9, 0, tzinfo=KST)
FOLDER_IDS = {
    name: f"31000000000000000{i:02d}"
    for i, name in enumerate(["inbox", "sent", "draft", "archive", "spam", "trash"], 1)
}
# What the benchmark's simulated agent counts as a request addressed to the
# user; no generated message contains it, only the planted triage mail.
REQUEST = re.compile(
    r"부탁|보내 주세요|제출해 주시기|회신|please (review|sign|send|reply)|could you please",
    re.IGNORECASE,
)


@dataclass
class Attachment:
    name: str
    size: int
    mime: str

    @property
    def payload(self) -> bytes:
        return random.Random(self.name).randbytes(self.size)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass
class Mail:
    id: str
    folder: str
    sent: int
    sender: tuple[str, str]
    subject: str
    paragraphs: list[str]
    files: list[Attachment] = field(default_factory=list)
    read: bool = True
    favorite: bool = False
    to: list[tuple[str, str]] = field(default_factory=lambda: [ME])

    @property
    def received(self) -> int:
        return self.sent + 4 + int(self.id) % 9

    @property
    def text(self) -> str:
        return "\n".join(self.paragraphs)

    @property
    def preview(self) -> str:
        return " ".join(self.paragraphs)[:200]

    @property
    def html(self) -> str:
        return "".join(f"<p>{html.escape(p)}</p>" for p in self.paragraphs)


KO_NOTICE = [
    "본 안내는 학내 구성원 전체를 대상으로 발송되었습니다.",
    "자세한 사항은 첨부 파일을 참고하시기 바랍니다.",
    "관련 문의는 담당 부서로 연락하시기 바랍니다.",
    "일정은 학내 사정에 따라 변경될 수 있으며, 변경 시 별도로 공지할 예정입니다.",
    "포털 공지사항 게시판에서도 동일한 내용을 확인할 수 있습니다.",
    "학생 여러분의 많은 관심과 참여를 바랍니다.",
    "신청은 선착순으로 마감되며 정원이 초과되면 조기 마감될 수 있습니다.",
    "이미 신청한 경우 본 메일은 무시하셔도 됩니다.",
    "해당 기간 이후에는 시스템 접속이 제한됩니다.",
    "원활한 진행을 위해 일정을 미리 확인하시기 바랍니다.",
    "본 메일은 발신 전용 주소에서 발송되었습니다.",
    "기타 자세한 내용은 학과 사무실로 문의하시기 바랍니다.",
    "행사 당일에는 주차 공간이 부족하므로 대중교통을 이용하시기 바랍니다.",
    "안전한 캠퍼스 환경 조성을 위해 협조해 주셔서 감사합니다.",
    "관련 규정은 학칙 및 시행세칙에 따릅니다.",
    "온라인 신청 후 확인 메일이 발송되지 않으면 스팸함을 확인하시기 바랍니다.",
]
EN_NOTICE = [
    "This notice is sent to all registered students.",
    "Details are given in the attached file.",
    "For questions, contact the office listed below.",
    "The schedule may change; any change will be announced separately.",
    "The same notice is posted on the KAIST portal.",
    "Seats are limited and registration may close early.",
    "If you have already registered, you may ignore this message.",
    "Access to the system is closed after the period ends.",
    "We appreciate your cooperation.",
    "Parking on campus is limited on the day of the event.",
    "This message was sent from an unmonitored address.",
    "Refreshments will be provided after the session.",
    "Students on leave of absence are not eligible for this program.",
]
KO_CHAT = [
    "어제 실험 결과 공유드립니다.",
    "학습이 3 epoch 정도 진행됐고 loss가 안정적으로 내려가고 있어요.",
    "다음 주 세미나 자료는 공유 폴더에 올려 두었습니다.",
    "점심은 동측 식당에서 먹었는데 괜찮았어요.",
    "서버 2번 노드가 오늘 오후에 재부팅될 예정이라고 합니다.",
    "참고로 데이터셋 경로가 /data/v2 로 바뀌었습니다.",
    "논문 초안 4장 그림을 조금 수정했습니다.",
    "내일은 연구실에 조금 늦게 도착할 것 같습니다.",
    "baseline 대비 정확도가 1.2%p 올랐습니다.",
    "회의록은 노션 페이지에 정리해 두었어요.",
]
EN_CHAT = [
    "Sharing the latest numbers from last night's run.",
    "The ablation without the auxiliary loss is about 2 points worse.",
    "I pushed the plotting script to the lab repository.",
    "The reading group moves to room 2201 next week.",
    "FYI, the cluster queue is long today.",
    "I fixed the off-by-one in the data loader.",
    "Slides from today's meeting are in the shared drive.",
]
WORDS = [
    "Sparse",
    "Robust",
    "Efficient",
    "Scalable",
    "Causal",
    "Contrastive",
    "Hierarchical",
    "Federated",
    "Diffusion",
    "Transformer",
    "Graph",
    "Attention",
    "Retrieval",
    "Alignment",
    "Reasoning",
    "Quantized",
    "Multimodal",
    "Streaming",
    "Neural",
    "Bayesian",
    "Adaptive",
    "Low-Rank",
    "Spectral",
]
TASKS = [
    "Language Modeling",
    "Speech Recognition",
    "Image Segmentation",
    "Code Generation",
    "Time-Series Forecasting",
    "Molecule Design",
    "Robot Control",
    "Recommendation",
]


def title(rng: random.Random) -> str:
    return f"{rng.choice(WORDS)} {rng.choice(WORDS)} Models for {rng.choice(TASKS)}"


def notice(rng: random.Random, office: str, ko: bool, n: int) -> list[str]:
    pool = KO_NOTICE if ko else EN_NOTICE
    head = (
        f"안녕하세요, {office}입니다."
        if ko
        else f"Dear members of KAIST, this is the {office}."
    )
    sign = (
        f"{office} 드림 (문의: 042-350-{rng.randint(1000, 9999)})"
        if ko
        else f"{office}, KAIST"
    )
    day, place = (
        rng.randint(1, 28),
        rng.choice(["창의학습관 터만홀", "KI빌딩 퓨전홀", "N1 101호", "E3-1 1501호"]),
    )
    details = (
        [
            f"1. 일시: {rng.randint(1, 12)}월 {day}일 {rng.randint(9, 17)}:00",
            f"2. 장소: {place}",
            "3. 대상: 학부 및 대학원 재학생",
            "4. 신청 방법: 포털 온라인 신청",
        ]
        if ko
        else [
            f"1. Date: day {day} of next month, {rng.randint(9, 17)}:00",
            f"2. Venue: {place}",
            "3. Eligibility: all enrolled students",
            "4. How to apply: KAIST portal",
        ]
    )
    return [
        head,
        *rng.sample(pool, min(n, len(pool))),
        *details,
        *rng.sample(pool, 2),
        sign,
    ]


def digest(rng: random.Random) -> list[str]:
    entries = [
        f"arXiv:24{rng.randint(10, 12)}.{rng.randint(10000, 99999)} Title: {title(rng)}. "
        f"Authors: {rng.choice(['Kim', 'Lee', 'Park', 'Chen', 'Smith', 'Garcia'])} et al. "
        f"Abstract: We study {rng.choice(WORDS).lower()} methods and report gains on "
        f"{rng.choice(TASKS).lower()} benchmarks. https://arxiv.org/abs/24{rng.randint(10, 12)}.{rng.randint(10000, 99999)}"
        for _ in range(rng.randint(12, 35))
    ]
    return [
        "New submissions in cs.LG and cs.CL received from your subscription.",
        *entries,
    ]


def scholar(rng: random.Random) -> list[str]:
    return [
        "Google Scholar Alert: new results for your query.",
        *(
            f"{title(rng)} - {rng.choice(['NeurIPS', 'ICML', 'ACL', 'arXiv'])} "
            f"{rng.randint(2022, 2026)}. ... we propose a {rng.choice(WORDS).lower()} approach ..."
            for _ in range(rng.randint(4, 9))
        ),
    ]


def github(rng: random.Random) -> list[str]:
    return [
        f"@{rng.choice(['jdoe', 'mkim', 'lab-bot', 'ychen'])} commented on this pull request.",
        rng.choice(EN_CHAT),
        "Reply to this email directly or view it on GitHub: "
        + f"https://github.com/kaist-lab/trainer/pull/{rng.randint(10, 900)}",
    ]


def chat(rng: random.Random, ko: bool) -> list[str]:
    pool = KO_CHAT if ko else EN_CHAT
    lines = rng.sample(pool, rng.randint(1, 4))
    if rng.random() < 0.3:
        lines.append("> " + rng.choice(pool))
    return lines


@dataclass
class Sender:
    who: tuple[str, str]
    weight: float
    unread: float
    attach: float
    subjects: list[str]
    body: str


SENDERS = [
    Sender(
        ("arXiv", "no-reply@arxiv.org"),
        15,
        0.9,
        0,
        ["cs daily Subj-class mailing {n}"],
        "digest",
    ),
    Sender(
        ("Google Scholar Alerts", "scholaralerts-noreply@google.com"),
        8,
        0.85,
        0,
        ["{t} - new results"],
        "scholar",
    ),
    Sender(
        ("GitHub", "notifications@github.com"),
        10,
        0.6,
        0,
        ["Re: [kaist-lab/trainer] {t} (PR #{n})"],
        "github",
    ),
    Sender(
        ("IEEE", "ieee-news@ieee.org"),
        4,
        0.95,
        0,
        ["IEEE Xplore: new issue of {t}"],
        "scholar",
    ),
    Sender(
        ("KAIST 포탈", "portal@kaist.ac.kr"),
        8,
        0.55,
        0.1,
        ["[포탈공지] {t} 안내", "[포탈공지] 시스템 점검 안내 ({n})"],
        "ko",
    ),
    Sender(
        ("학사팀", "academic@kaist.ac.kr"),
        5,
        0.3,
        0.3,
        [
            "[학사] 성적 정정 기간 안내",
            "[학사] 휴학 및 복학 신청 안내",
            "[학사] 기말고사 시간표 공지",
            "[학사] 졸업 사정 일정 안내",
        ],
        "ko",
    ),
    Sender(
        ("대학원 교학팀", "grad@kaist.ac.kr"),
        3,
        0.3,
        0.3,
        ["[대학원] 학위청구논문 제출 안내", "[대학원] 장학금 신청 안내"],
        "ko",
    ),
    Sender(
        ("Office of International Affairs", "oia@kaist.ac.kr"),
        3,
        0.4,
        0.2,
        [
            "[OIA] Visa Extension Notice",
            "[OIA] Global Lounge Event",
            "[OIA] Language Exchange Program",
        ],
        "en",
    ),
    Sender(
        ("정보통신팀", "it-help@kaist.ac.kr"),
        4,
        0.5,
        0.1,
        [
            "[정보통신팀] 네트워크 작업 안내",
            "[IT] Phishing mail warning",
            "[정보통신팀] 소프트웨어 라이선스 안내",
        ],
        "ko",
    ),
    Sender(
        ("KAIST 도서관", "library@kaist.ac.kr"),
        3,
        0.6,
        0,
        ["[도서관] 대출 도서 반납 예정 안내", "[도서관] 전자저널 이용 교육"],
        "ko",
    ),
    Sender(
        ("안전팀", "safety@kaist.ac.kr"),
        2,
        0.4,
        0.4,
        ["[안전팀] 연구실 정기점검 안내", "[안전팀] 소방 훈련 안내"],
        "ko",
    ),
    Sender(
        ("전기및전자공학부", "ee-all@kaist.ac.kr"),
        8,
        0.5,
        0.2,
        ["[EE Seminar] {t}", "[전기및전자공학부] 학과 행사 안내"],
        "en",
    ),
    Sender(
        ("카이스트 생협", "coop@kaist.ac.kr"),
        2,
        0.8,
        0,
        ["[생협] 이번 주 식단 안내", "[생협] 할인 행사"],
        "ko",
    ),
    Sender(
        ("OpenReview", "noreply@openreview.net"),
        3,
        0.3,
        0,
        ["[NeurIPS 2026] {t} paper status update"],
        "github",
    ),
    Sender(
        ("김민수", "minsu.kim@kaist.ac.kr"),
        4,
        0.05,
        0.15,
        ["Re: 주간 미팅 자료", "논문 진행 상황", "Re: {t}"],
        "ko-chat",
    ),
    Sender(
        ("이지은", "jieun.lee@kaist.ac.kr"),
        5,
        0.05,
        0.15,
        ["실험 결과 공유", "Re: 세미나 자료", "서버 관련"],
        "ko-chat",
    ),
    Sender(
        ("Daniel Park", "dpark@kaist.ac.kr"),
        4,
        0.05,
        0.15,
        ["weekly update", "Re: {t}", "plots for the draft"],
        "en-chat",
    ),
    Sender(
        ("박서준", "seojun.park@kaist.ac.kr"),
        3,
        0.05,
        0.1,
        ["Re: 데이터셋 경로", "점심 메뉴", "Re: 연구실 청소"],
        "ko-chat",
    ),
    Sender(
        ("Jane Smith", "jsmith@cs.example.edu"),
        1,
        0.1,
        0.2,
        ["Re: collaboration on {t}", "follow-up"],
        "en-chat",
    ),
]
FILE_NAMES = [
    "안내문.pdf",
    "신청서 양식.hwp",
    "Schedule_{y}.xlsx",
    "poster.png",
    "발표자료_{y}.pptx",
    "Guideline (EN).pdf",
    "참가자 명단.xlsx",
    "results_{y}.csv",
]


def make_body(rng: random.Random, sender: Sender) -> list[str]:
    match sender.body:
        case "digest":
            return digest(rng)
        case "scholar":
            return scholar(rng)
        case "github":
            return github(rng)
        case "ko" | "en":
            return notice(rng, sender.who[0], sender.body == "ko", rng.randint(3, 10))
        case "ko-chat" | "en-chat":
            return chat(rng, sender.body == "ko-chat")
    raise ValueError(sender.body)


def epoch(year: int, month: int, day: int) -> int:
    return int(datetime(year, month, day, 10, tzinfo=KST).timestamp())


@dataclass
class Truth:
    """The known answers of the benchmark's tasks."""

    orientation_room: str
    classroom: str
    certificate: tuple[str, str]
    enrollment_years: str
    triage_ids: set[str]
    academic_unread: int


def planted() -> tuple[list[Mail], list[Mail]]:
    """Messages the tasks ask about with look-alikes around them, and the
    requests the triage task must find. What tells the look-alikes apart sits
    past the 200-character preview."""
    mails: list[Mail] = []
    oia = ("Office of International Affairs", "oia@kaist.ac.kr")
    rooms = [
        "E11 Room 201",
        "N1 Room 102",
        "E3-1 Room 1501",
        "W1-3 Room 2104",
        "KI Building (E4) Room 412",
    ]
    semesters = [(y, s) for y in range(2022, 2027) for s in ("Spring", "Fall")][:9]
    for i, (year, season) in enumerate(semesters):
        body = [
            "Dear exchange students,",
            (
                "On behalf of the Office of International Affairs, welcome to KAIST. "
                "This message explains the orientation for newly arrived exchange and "
                "visiting students, which covers campus life, immigration rules, health "
                "insurance and academic regulations."
            ),
            f"This orientation is for the {season} {year} semester.",
            *EN_NOTICE[:6],
            f"Date and time: {season} {year} orientation day, 14:00-17:00.",
            f"Location: {rooms[i % len(rooms)]}",
            *EN_NOTICE[6:],
        ]
        month = 2 if season == "Spring" else 8
        for day, subject in [
            (10, "[OIA] Exchange Student Orientation"),
            (17, "[OIA] Reminder: Exchange Student Orientation"),
        ]:
            mails.append(Mail("", "inbox", epoch(year, month, day), oia, subject, body))

    academic = ("학사팀", "academic@kaist.ac.kr")
    intro = (
        "안녕하세요, 학사팀입니다. 수강생 여러분의 원활한 수업 진행을 위하여 아래 교과목의 강의실이 "
        "변경되었음을 알려드립니다. 변경된 강의실은 다음 주 수업부터 적용되며, 강의실 배정 현황은 "
        "포털 학사 시스템의 수업 메뉴에서도 확인할 수 있습니다. 수업 첫 주에는 이전 강의실 앞에 "
        "안내문이 게시됩니다."
    )
    courses = [
        "EE209",
        "CS320",
        "EE305",
        "CS330",
        "MAS250",
        "EE488",
        "CS341",
        "EE362",
        "CS376",
    ]
    halls = ["N1 #117", "E3-1 #1101", "E11 #311", "N4 #1318", "W1-1 #3444", "E2 #1225"]
    cs492 = {5: "W1-1 #3444", 20: "E11 #305"}
    for i in range(36):
        month = 2 + i * 3 // 2
        course = "CS492" if i in cs492 else courses[i % len(courses)]
        body = [
            intro,
            f"교과목: {course} (분반 A)",
            "기존 강의실: E3-1 #1501",
            f"변경 강의실: {cs492.get(i, halls[i % len(halls)])}",
            *KO_NOTICE[:3],
            "학사팀 드림",
        ]
        sent = epoch(2022 + month // 12, month % 12 + 1, 3 + i % 20)
        mails.append(Mail("", "inbox", sent, academic, "[학사] 강의실 변경 안내", body))
    exam = [
        "안녕하세요, 학사팀입니다. 기말고사 시간표를 안내드립니다.",
        *(f"{c}: 12월 {d}일 09:00" for d, c in enumerate([*courses, "CS492"], 10)),
    ]
    mails.append(
        Mail(
            "",
            "inbox",
            epoch(2025, 11, 20),
            academic,
            "[학사] 기말고사 시간표 공지",
            exam,
        )
    )
    prof = ("김민수", "minsu.kim@kaist.ac.kr")
    mails.append(
        Mail(
            "",
            "inbox",
            epoch(2025, 8, 25),
            prof,
            "CS492 강의계획서",
            ["CS492 수업 조교 분들께 강의계획서 초안 공유드립니다.", *KO_CHAT[:2]],
        )
    )

    safety = ("안전팀", "safety@kaist.ac.kr")
    guide = Attachment("안전교육_수강방법_안내.pdf", 84_211, "application/pdf")
    for year in range(2022, 2026):
        files = [
            Attachment(
                f"연구실안전교육_이수증_{year}.pdf", 131_072 + year, "application/pdf"
            ),
            guide,
        ]
        certificate = Mail(
            "",
            "inbox",
            epoch(year, 6, 14),
            safety,
            "[안전팀] 연구실 안전교육 이수증 발급 안내",
            notice(random.Random(year), "안전팀", True, 6),
            files,
        )
        mails.append(
            Mail(
                "",
                "inbox",
                epoch(year, 3, 2),
                safety,
                "[안전팀] 연구실 안전교육 수강 안내",
                notice(random.Random(-year), "안전팀", True, 5),
                [guide],
            )
        )
        mails.append(certificate)

    grad = ("대학원 교학팀", "grad@kaist.ac.kr")
    topics = ["목적", "정의", "적용 범위", "학위 과정", "이수 학점", "지도교수"]
    for year, years in [(2024, "7년"), (2026, "8년")]:
        articles = [
            f"제57조 (재학연한) 석박사통합과정의 재학연한은 {years}으로 하며, 휴학 기간은 재학연한에 산입하지 아니한다."
            if n == 57
            else f"제{n}조 ({topics[n % 6]}) "
            + " ".join(KO_NOTICE[(n + k) % len(KO_NOTICE)] for k in range(5))
            for n in range(1, 61)
        ]
        head = f"안녕하세요, 대학원 교학팀입니다. {year}년 학위과정 운영 규정 개정 내용을 아래와 같이 안내드립니다. 개정 규정은 공포한 날부터 시행합니다."
        mails.append(
            Mail(
                "",
                "inbox",
                epoch(year, 3, 3),
                grad,
                "[대학원] 학위과정 운영 규정 개정 안내",
                [head, *articles, "대학원 교학팀 드림"],
            )
        )

    requests = [
        (
            prof,
            "Re: 주간 미팅 자료",
            [*KO_CHAT[:6], "그리고 금요일까지 NeurIPS rebuttal 초안을 보내 주세요."],
        ),
        (
            ("이지은", "jieun.lee@kaist.ac.kr"),
            "서버 계정 관련",
            ["오늘 중으로 GPU 서버 계정 비밀번호 변경 부탁드립니다.", *KO_CHAT[2:4]],
        ),
        (
            ("Daniel Park", "dpark@kaist.ac.kr"),
            "Paper review",
            ["Could you please review section 4 by Thursday?", *EN_CHAT[:2]],
        ),
        (
            ("Jane Smith", "jsmith@cs.example.edu"),
            "Data sharing agreement",
            ["Please sign and return the attached agreement by Nov 20.", EN_CHAT[3]],
        ),
        (
            ("전기및전자공학부 행정팀", "ee-office@kaist.ac.kr"),
            "[EE] 조교 근무일지 제출 요청",
            [
                "조교 여러분, 11월 14일까지 10월 근무일지를 제출해 주시기 바랍니다.",
                *KO_NOTICE[:2],
            ],
        ),
        (
            ("박서준", "seojun.park@kaist.ac.kr"),
            "회식 장소",
            [*KO_CHAT[3:9], "다음 주 목요일 회식 참석 여부 회신 부탁드려요."],
        ),
    ]
    request_mails = [
        Mail(
            "",
            "inbox",
            int(NOW.timestamp()) - 3600 * (4 + 9 * i),
            who,
            subject,
            body,
            [Attachment("data_sharing_agreement.pdf", 51_200, "application/pdf")]
            if i == 3
            else [],
            read=False,
        )
        for i, (who, subject, body) in enumerate(requests)
    ]
    return mails + request_mails, request_mails


def generate() -> tuple[list[Mail], Truth]:
    rng = random.Random(7)
    inbox, requests = planted()
    span = int(NOW.timestamp()) - int(START.timestamp())
    weights = [s.weight for s in SENDERS]
    generated: list[tuple[Mail, Sender]] = []
    while len(inbox) < INBOX_TOTAL:
        sender = rng.choices(SENDERS, weights)[0]
        sent = int(START.timestamp()) + rng.randrange(span)
        year = datetime.fromtimestamp(sent, KST).year
        subject = rng.choice(sender.subjects).format(
            t=title(rng), n=rng.randint(100, 999)
        )
        files = [
            Attachment(
                rng.choice(FILE_NAMES).format(y=year),
                rng.randint(20_000, 400_000),
                "application/octet-stream",
            )
            for _ in range(rng.randint(1, 2))
            if rng.random() < sender.attach
        ]
        mail = Mail(
            "",
            "inbox",
            sent,
            sender.who,
            subject,
            make_body(rng, sender),
            files,
            favorite=rng.random() < 0.01,
        )
        inbox.append(mail)
        generated.append((mail, sender))
    # The rest of the unread, by weighted sampling without replacement (Efraimidis-Spirakis).
    unread = INBOX_UNREAD - len(requests)
    keyed = sorted(
        generated, key=lambda pair: rng.random() ** (1 / pair[1].unread), reverse=True
    )
    for mail, _ in keyed[:unread]:
        mail.read = False

    others: list[Mail] = []
    chatty = [s.who for s in SENDERS if s.body.endswith("chat")]
    for folder, count in [("sent", 416), ("archive", 6), ("spam", 109), ("trash", 22)]:
        for _ in range(count):
            sent = int(START.timestamp()) + rng.randrange(span)
            if folder == "sent":
                mail = Mail(
                    "",
                    folder,
                    sent,
                    ME,
                    f"Re: {title(rng)}",
                    chat(rng, rng.random() < 0.5),
                    to=[rng.choice(chatty)],
                )
            else:
                promo = f"Special offer {rng.randint(1, 99)}% off"
                mail = Mail(
                    "",
                    folder,
                    sent,
                    ("Promo", "deals@shop.example"),
                    promo,
                    EN_CHAT[:2],
                    read=folder != "spam",
                )
            others.append(mail)

    mails = sorted(inbox + others, key=lambda m: m.sent)
    for i, mail in enumerate(mails):
        mail.id = str(
            4_400_000_000_000_000_000 + (i + 1) * 1_000 + rng.randrange(1_000)
        )
    for mail in mails:
        if mail not in requests and REQUEST.search(mail.text):
            raise AssertionError(
                f"a generated message reads as a request: {mail.subject}"
            )
    newest_unread = sorted(
        (m for m in mails if m.folder == "inbox" and not m.read),
        key=lambda m: -m.received,
    )[:50]
    certificate = next(
        f for m in mails for f in m.files if f.name == "연구실안전교육_이수증_2023.pdf"
    )
    truth = Truth(
        orientation_room="KI Building (E4) Room 412",
        classroom="E11 #305",
        certificate=(certificate.name, certificate.digest),
        enrollment_years="8년",
        triage_ids={m.id for m in newest_unread if REQUEST.search(m.text)},
        academic_unread=sum(
            m.folder == "inbox" and not m.read and m.sender[1] == "academic@kaist.ac.kr"
            for m in mails
        ),
    )
    assert sum(m.folder == "inbox" for m in mails) == INBOX_TOTAL
    assert sum(m.folder == "inbox" and not m.read for m in mails) == INBOX_UNREAD
    assert truth.triage_ids == {m.id for m in requests}
    return mails, truth


def iso(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, KST).isoformat()


def person(who: tuple[str, str]) -> Json:
    return {"type": "emailUser", "emailUser": {"name": who[0], "emailAddress": who[1]}}


def envelope(result: object) -> bytes:
    body = {
        "header": {"resultCode": 0, "resultMessage": "", "isSuccessful": True},
        "result": result,
    }
    return json.dumps(body, ensure_ascii=False).encode()


class Mailbox:
    """The mailbox as Dooray serves it, with the read state reading changes."""

    def __init__(self, mails: list[Mail]) -> None:
        self.mails = mails
        self.by_id = {m.id: m for m in mails}
        listed = json.loads((FIXTURES / "mails-list.json").read_text())["result"]
        self.item_template = listed["contents"][0]
        self.classified_template = listed["references"]["classifiedMap"][
            "younghee@example.com"
        ]
        self.detail_template = json.loads((FIXTURES / "mail-detail.json").read_text())[
            "result"
        ]
        self.folders_template = json.loads(
            (FIXTURES / "mail-folders-system.json").read_text()
        )["result"]

    def item(self, mail: Mail, preview: bool) -> Json:
        item = copy.deepcopy(self.item_template)
        item.update(
            id=mail.id,
            createdAt=iso(mail.received),
            updatedAt=iso(mail.received),
            subject=mail.subject,
            fileCount=len(mail.files),
            folderId=FOLDER_IDS[mail.folder],
        )
        summary = item["mailSummary"]
        summary.update(
            sentAt=iso(mail.sent),
            mimeSize=2_000 + len(mail.html) + sum(f.size for f in mail.files),
        )
        summary["previewText"] = mail.preview if preview else None
        summary["flags"].update(read=mail.read, favorite=mail.favorite)
        item["annotations"] = {"favorited": mail.favorite}
        item["users"].update(
            {
                "from": person(mail.sender),
                "envFrom": person(mail.sender),
                "froms": [person(mail.sender)],
                "to": [person(t) for t in mail.to],
                "cc": [],
            }
        )
        return item

    def references(self, mails: list[Mail]) -> Json:
        classified = {}
        for mail in mails:
            entry = copy.deepcopy(self.classified_template)
            entry["emailUser"] = {"emailAddress": mail.sender[1]}
            classified[mail.sender[1]] = entry
        folders = {
            FOLDER_IDS[m.folder]: {
                "id": FOLDER_IDS[m.folder],
                "name": m.folder,
                "type": "system",
            }
            for m in mails
        }
        return {"folderMap": folders, "classifiedMap": classified}

    def folders(self) -> bytes:
        result = copy.deepcopy(self.folders_template)
        for folder in result["contents"]:
            inside = [m for m in self.mails if m.folder == folder["name"]]
            folder.update(
                id=FOLDER_IDS[folder["name"]],
                totalCount=len(inside),
                unreadCount=sum(not m.read for m in inside),
            )
        return envelope(result)

    def list(self, query: dict[str, str]) -> bytes:
        folder = query.get("folderName") or next(
            n for n, i in FOLDER_IDS.items() if i == query["folderId"]
        )
        rows = [
            m
            for m in self.mails
            if m.folder == folder
            and (query.get("read") != "false" or not m.read)
            and (query.get("favorited") != "true" or m.favorite)
            and (query.get("hasAttachment") != "true" or m.files)
        ]
        rows.sort(
            key=lambda m: (m.received, m.id), reverse=query.get("order") == "-createdAt"
        )
        page, size = int(query["page"]), int(query["size"])
        shown = rows[page * size : (page + 1) * size]
        preview = query.get("preview") == "true"
        return envelope(
            {
                "totalCount": len(rows),
                "references": self.references(shown),
                "contents": [self.item(m, preview) for m in shown],
            }
        )

    def search(self, body: Json, preview: bool) -> bytes:
        def has(haystack: str, needles: list[str]) -> bool:
            return all(n.lower() in haystack.lower() for n in needles)

        def matches(m: Mail) -> bool:
            sender = " ".join(m.sender)
            to = " ".join(" ".join(t) for t in m.to)
            files = " ".join(f.name for f in m.files)
            folders = body.get("folderNames") or [
                name
                for name, id in FOLDER_IDS.items()
                if id in body.get("folderIds", [])
            ]
            return (
                (
                    m.folder in folders
                    if folders
                    else m.folder not in body.get("exceptFolders", [])
                )
                and has(
                    f"{m.subject} {m.text} {sender} {to} {files}",
                    body.get("all", []),
                )
                and has(m.subject, body.get("subjects", []))
                and has(m.text, body.get("bodies", []))
                and has(files, body.get("fileNames", []))
                and has(sender, body.get("fromList", []))
                and has(to, body.get("toList", []))
                and has("", body.get("ccList", []))
                and (body.get("seenFlag") is not False or not m.read)
                and (not body.get("favoritedFlag") or m.favorite)
                and (not body.get("attachedFlag") or bool(m.files))
                and (
                    "since" not in body
                    or m.sent >= int(datetime.fromisoformat(body["since"]).timestamp())
                )
                and (
                    "before" not in body
                    or m.sent <= int(datetime.fromisoformat(body["before"]).timestamp())
                )
            )

        hits = sorted(
            filter(matches, self.mails),
            key=lambda m: (m.sent, m.id),
            reverse=body.get("order") == "-createdAt",
        )
        page, size = body["page"], body["size"]
        shown = hits[:2000][page * size : (page + 1) * size]
        result: Json = {
            "totalCount": min(len(hits), 2000),
            "contents": [
                {
                    "id": m.id,
                    "subject": m.subject,
                    "sentAt": "1970-01-01T09:00:00+09:00",
                    "matchedFiles": [
                        f.name
                        for f in m.files
                        if has(f.name, body.get("fileNames", []))
                    ]
                    if body.get("fileNames")
                    else [],
                }
                for m in shown
            ],
        }
        if shown:
            result["references"] = {
                "folderMap": self.references(shown)["folderMap"],
                "mailMap": {m.id: self.item(m, preview) for m in shown},
            }
        return envelope(result)

    def detail(self, mail: Mail) -> bytes:
        result = copy.deepcopy(self.detail_template)
        content = result["content"]
        content.update(
            id=mail.id,
            originMailId=mail.id,
            subject=mail.subject,
            createdAt=iso(mail.received),
            folderId=FOLDER_IDS[mail.folder],
        )
        content["mail"].update(sentAt=iso(mail.sent))
        content["mail"]["flags"].update(read=mail.read, favorite=mail.favorite)
        content["users"].update(
            {
                "from": person(mail.sender),
                "envFrom": person(mail.sender),
                "froms": [person(mail.sender)],
                "to": [person(t) for t in mail.to],
                "cc": [],
                "bcc": [],
                "replyTo": [],
            }
        )
        content["body"] = {"mimeType": "text/html", "content": mail.html}
        part = copy.deepcopy(self.detail_template["content"]["fileList"][0])
        content["fileList"] = [
            dict(
                part,
                name=f.name,
                size=f.size,
                mimeType=f.mime,
                partNumber=n,
                extension=f.name.rsplit(".", 1)[-1],
                downloadUrl=f"/mails/{mail.id}/parts/{n}?type=raw&t=1",
            )
            for n, f in enumerate(mail.files, 2)
        ]
        mail.read = True
        return envelope(result)


@dataclass
class Exchange:
    sent: int
    received: int


class Counted(io.BufferedIOBase):
    """A handler's socket stream that counts the bytes crossing it."""

    def __init__(self, stream: io.BufferedIOBase) -> None:
        super().__init__()
        self.stream = stream
        self.bytes = 0

    @override
    def read(self, size: int | None = -1) -> bytes:
        data = self.stream.read(size)
        self.bytes += len(data)
        return data

    @override
    def readline(self, size: int | None = -1) -> bytes:
        data = self.stream.readline(size)
        self.bytes += len(data)
        return data

    @override
    def write(self, data: Buffer) -> int:
        self.bytes += len(memoryview(data))
        return self.stream.write(data)

    @override
    def flush(self) -> None:
        self.stream.flush()

    def take(self) -> int:
        """The bytes counted since the last take."""
        counted, self.bytes = self.bytes, 0
        return counted


class Server:
    """Serves `mailbox` on a loopback port and records every exchange."""

    def __init__(self, mailbox: Mailbox, latency: float = 0.0) -> None:
        self.mailbox = mailbox
        self.latency = latency
        self.log: list[Exchange] = []
        bench = self

        class Handler(BaseHTTPRequestHandler):
            @override
            def setup(self) -> None:
                super().setup()
                self.rfile, self.wfile = Counted(self.rfile), Counted(self.wfile)

            def do_GET(self) -> None:
                self.answer(b"")

            def do_POST(self) -> None:
                self.answer(self.rfile.read(int(self.headers["Content-Length"])))

            def answer(self, request: bytes) -> None:
                status, kind, body = bench.route(self.command, self.path, request)
                if bench.latency:
                    time.sleep(bench.latency)
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                incoming, outgoing = self.rfile, self.wfile
                assert isinstance(incoming, Counted) and isinstance(outgoing, Counted)
                bench.log.append(Exchange(incoming.take(), outgoing.take()))

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.http.server_port}"

    def route(self, method: str, target: str, request: bytes) -> tuple[int, str, bytes]:
        url = urlsplit(target)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        json_type = "application/json;charset=UTF-8"
        if url.path == "/v2/wapi/mail-folders":
            return (
                200,
                json_type,
                self.mailbox.folders()
                if query["type"] == "system"
                else envelope({"totalCount": 0, "contents": []}),
            )
        if url.path == "/v2/wapi/mails" and method == "GET":
            return 200, json_type, self.mailbox.list(query)
        if url.path == "/v2/wapi/mails/search":
            return (
                200,
                json_type,
                self.mailbox.search(
                    json.loads(request), query.get("preview") == "true"
                ),
            )
        if m := re.fullmatch(r"/v2/wapi/mails/(\d+)", url.path):
            return 200, json_type, self.mailbox.detail(self.mailbox.by_id[m[1]])
        if m := re.fullmatch(r"/mails/(\d+)/parts/(\d+)", url.path):
            file = self.mailbox.by_id[m[1]].files[int(m[2]) - 2]
            return 200, file.mime, file.payload
        return 404, "text/plain", b"not found"
