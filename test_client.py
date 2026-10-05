import argparse
import time

import requests


BASE = "http://127.0.0.1:5000"


CASES = [

    (
        "normal",
        "/api/demo?q=hello",
        None
    ),

    (
        "sqli",
        "/api/demo?q=' OR 1=1 --",
        None
    ),

    (
        "xss",
        "/api/demo?q=%3Cscript%3Ealert(1)%3C/script%3E",
        None
    ),

    (
        "traversal",
        "/api/demo?file=../../etc/passwd",
        None
    ),

    (
        "lfi",
        "/api/demo?file=php://filter/resource=/etc/passwd",
        None
    ),

    (
        "command",
        "/api/demo?cmd=%3B%20whoami",
        None
    ),
]


def run_case(
    name,
    path
):

    response = requests.get(
        BASE + path,
        timeout=5
    )

    print(
        f"{name:12} -> "
        f"HTTP {response.status_code}: "
        f"{response.text[:220]}"
    )


def main():

    parser = argparse.ArgumentParser(
        description=
            "SentinelShield authorized local-lab traffic simulator"
    )

    parser.add_argument(
        "--mode",
        choices=[
            "normal",
            "attacks",
            "flood",
            "all"
        ],
        default="all"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=40
    )

    args = parser.parse_args()


    if args.mode in {
        "normal",
        "all"
    }:

        run_case(
            "normal",
            "/api/demo?q=hello"
        )


    if args.mode in {
        "attacks",
        "all"
    }:

        for name, path, _ in CASES[1:]:

            run_case(
                name,
                path
            )


    if args.mode in {
        "flood",
        "all"
    }:

        print(
            f"\nFlood test: "
            f"{args.count} requests"
        )

        for i in range(
            args.count
        ):

            response = requests.get(
                BASE +
                f"/api/demo?seq={i}",
                timeout=5
            )

            print(
                f"flood #{i + 1:02d} "
                f"-> {response.status_code}"
            )

            if response.status_code == 429:
                break

            time.sleep(0.05)


    print(
        "\nOpen /dashboard "
        "to review the resulting "
        "summary and events."
    )


if __name__ == "__main__":
    main()
