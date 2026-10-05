from flask import (
    jsonify,
    request,
    g
)


EXEMPT_PREFIXES = (
    "/dashboard",
    "/api/dashboard",
    "/static/"
)


def _client_ip() -> str:
    """
    Do not blindly trust X-Forwarded-For.
    A trusted reverse-proxy configuration should be used
    before enabling proxy-derived client IPs.
    """
    return request.remote_addr or "unknown"


def install_waf(
    app,
    detector,
    limiter,
    audit_logger
):

    @app.before_request
    def inspect_request():

        if request.path.startswith(
            EXEMPT_PREFIXES
        ):
            return None

        ip = _client_ip()

        # --------------------------------
        # 1. RATE LIMIT CHECK
        # --------------------------------

        rate = limiter.check(ip)

        if not rate["allowed"]:

            event = {
                "event":
                    "request_decision",

                "decision":
                    "blocked",

                "reason":
                    "rate_limit",

                "category":
                    "Brute Force / Flooding",

                "severity":
                    "High",

                "method":
                    request.method,

                "path":
                    request.path,

                "ip":
                    ip,

                "request_count":
                    rate["count"]
            }

            audit_logger.log(
                event
            )

            g.sentinel_event = event

            response = jsonify({
                "status":
                    "blocked",

                "reason":
                    "rate_limit",

                "message":
                    "Request rate exceeded the configured threshold."
            })

            response.status_code = 429

            response.headers[
                "Retry-After"
            ] = str(
                rate["retry_after"]
            )

            return response

        # --------------------------------
        # 2. SIGNATURE INSPECTION
        # --------------------------------

        result = detector.inspect(
            request
        )

        if result["detected"]:

            categories = sorted({
                item["category"]
                for item
                in result["findings"]
            })

            event = {
                "event":
                    "request_decision",

                "decision":
                    "blocked",

                "reason":
                    "signature_match",

                "category":
                    (
                        categories[0]
                        if len(categories) == 1
                        else "Multiple"
                    ),

                "categories":
                    categories,

                "severity":
                    result["severity"],

                "method":
                    request.method,

                "path":
                    request.path,

                "ip":
                    ip,

                "findings":
                    result["findings"]
            }

            audit_logger.log(
                event
            )

            g.sentinel_event = event

            return jsonify({
                "status":
                    "blocked",

                "reason":
                    "signature_match",

                "severity":
                    result["severity"],

                "categories":
                    categories,

                "message":
                    "Request blocked by SentinelShield inspection rules."
            }), 403

        # --------------------------------
        # 3. ALLOWED REQUEST
        # --------------------------------

        event = {
            "event":
                "request_decision",

            "decision":
                "allowed",

            "reason":
                "no_detection",

            "category":
                "None",

            "severity":
                "None",

            "method":
                request.method,

            "path":
                request.path,

            "ip":
                ip,

            "request_count":
                rate["count"]
        }

        audit_logger.log(
            event
        )

        g.sentinel_event = event

        return None

    @app.after_request
    def security_headers(
        response
    ):

        response.headers.setdefault(
            "X-Content-Type-Options",
            "nosniff"
        )

        response.headers.setdefault(
            "X-Frame-Options",
            "DENY"
        )

        response.headers.setdefault(
            "Referrer-Policy",
            "no-referrer"
        )

        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'"
        )

        if request.is_secure:

            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains"
            )

        return response
