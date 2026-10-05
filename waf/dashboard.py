from collections import Counter
from functools import wraps

from flask import (
    Blueprint,
    Response,
    jsonify,
    render_template,
    request
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)


def install_dashboard(
    app,
    audit_logger,
    limiter,
    username: str,
    password: str
):

    bp = Blueprint(
        "dashboard",
        __name__
    )

    password_hash = generate_password_hash(
        password
    )

    def auth_required(function):

        @wraps(function)
        def wrapped(*args, **kwargs):

            auth = request.authorization

            if (
                not auth
                or auth.username != username
                or not check_password_hash(
                    password_hash,
                    auth.password
                )
            ):

                response = Response(
                    "Dashboard authentication required",
                    401
                )

                response.headers[
                    "WWW-Authenticate"
                ] = (
                    'Basic realm="SentinelShield Dashboard"'
                )

                return response

            return function(
                *args,
                **kwargs
            )

        return wrapped

    @bp.get("/dashboard")
    @auth_required
    def dashboard():

        return render_template(
            "dashboard.html"
        )

    @bp.get(
        "/api/dashboard/summary"
    )
    @auth_required
    def summary():

        events = audit_logger.read_recent(
            5000
        )

        blocked = [
            e for e in events
            if e.get("decision") == "blocked"
        ]

        malicious = [
            e for e in blocked
            if e.get("reason")
            == "signature_match"
        ]

        rate = [
            e for e in blocked
            if e.get("reason")
            == "rate_limit"
        ]

        categories = Counter()
        ips = Counter()

        for event in blocked:

            ips[
                event.get(
                    "ip",
                    "unknown"
                )
            ] += 1

            for category in event.get(
                "categories",
                [
                    event.get(
                        "category",
                        "Unknown"
                    )
                ]
            ):
                categories[category] += 1

        return jsonify({

            "total_events":
                len(events),

            "malicious_requests_detected":
                len(malicious),

            "rate_limit_blocks":
                len(rate),

            "blocked_requests":
                len(blocked),

            "allowed_requests":
                sum(
                    e.get("decision")
                    == "allowed"
                    for e in events
                ),

            "category_distribution":
                dict(
                    categories.most_common()
                ),

            "repeatedly_flagged_ips": [
                {
                    "ip": ip,
                    "blocked_count": count
                }

                for ip, count
                in ips.most_common(20)
            ],

            "recent_events":
                events[:50],

            "rate_limiter":
                limiter.snapshot()
        })

    @bp.get(
        "/api/dashboard/logs"
    )
    @auth_required
    def logs():

        try:
            limit = min(
                max(
                    int(
                        request.args.get(
                            "limit",
                            "200"
                        )
                    ),
                    1
                ),
                1000
            )

        except ValueError:
            limit = 200

        return jsonify({
            "events":
                audit_logger.read_recent(
                    limit
                )
        })

    app.register_blueprint(bp)
