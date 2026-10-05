from flask import (
    Flask,
    jsonify,
    request
)

from config import Settings

from waf.detector import (
    ThreatDetector
)

from waf.rate_limiter import (
    SlidingWindowRateLimiter
)

from waf.logger import (
    JsonAuditLogger
)

from waf.middleware import (
    install_waf
)

from waf.dashboard import (
    install_dashboard
)


def create_app():

    settings = Settings.from_env()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )

    app.config.update(
        MAX_CONTENT_LENGTH=
            settings.max_body_bytes
    )

    detector = ThreatDetector()

    limiter = SlidingWindowRateLimiter(
        settings.rate_limit_max,
        settings.rate_limit_window,
        settings.rate_limit_block_seconds
    )

    audit_logger = JsonAuditLogger(
        settings.log_file,
        settings.log_max_bytes,
        settings.log_backups
    )

    install_waf(
        app,
        detector,
        limiter,
        audit_logger
    )

    install_dashboard(
        app,
        audit_logger,
        limiter,
        settings.dashboard_user,
        settings.dashboard_password
    )

    @app.get("/")
    def home():

        return jsonify({

            "application":
                "SentinelShield",

            "purpose":
                "Educational Web Application Firewall / IDS laboratory",

            "protected_endpoints": [
                "/api/demo"
            ],

            "dashboard":
                "/dashboard",

            "status_codes": {
                "allowed": 200,
                "signature_block": 403,
                "rate_limit_block": 429
            }
        })

    @app.route(
        "/api/demo",
        methods=["GET", "POST"]
    )
    def demo():

        return jsonify({

            "status":
                "allowed",

            "message":
                "The request passed SentinelShield inspection.",

            "method":
                request.method,

            "received":
                (
                    request.get_json(
                        silent=True
                    )
                    if request.is_json
                    else request.args.to_dict(
                        flat=True
                    )
                )
        })

    @app.errorhandler(413)
    def too_large(_error):

        return jsonify({
            "status":
                "blocked",

            "reason":
                "request_too_large"
        }), 413

    @app.errorhandler(500)
    def server_error(_error):

        return jsonify({
            "status":
                "error",

            "message":
                "Internal server error."
        }), 500

    return app


app = create_app()


if __name__ == "__main__":

    settings = Settings.from_env()

    app.run(
        host=settings.host,
        port=settings.port,
        debug=settings.debug
    )
