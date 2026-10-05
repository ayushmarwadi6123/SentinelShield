"use strict";

/*
 * ============================================================
 * SENTINELSHIELD SOC DASHBOARD
 * ============================================================
 *
 * Frontend responsibilities:
 *
 *   Backend API
 *        ↓
 *   Fetch telemetry
 *        ↓
 *   Normalize data
 *        ↓
 *   Render SOC interface
 *
 * No artificial security events are generated here.
 *
 * Everything displayed by the dashboard comes from the
 * SentinelShield backend.
 * ============================================================
 */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const SUMMARY_ENDPOINT =
    "/api/dashboard/summary";

const REFRESH_INTERVAL =
    5000;


/* ============================================================
   DOM
   ============================================================ */

function $(id) {
    return document.getElementById(id);
}


/* ============================================================
   SECURITY
   ============================================================ */

function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* ============================================================
   NUMBER
   ============================================================ */

function number(value) {

    const parsed =
        Number(value);

    return Number.isFinite(parsed)
        ? parsed
        : 0;
}


/* ============================================================
   DATE
   ============================================================ */

function formatTime(timestamp) {

    if (!timestamp) {
        return "-";
    }

    const date =
        new Date(timestamp);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(timestamp);
    }

    return date.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


/* ============================================================
   RELATIVE TIME
   ============================================================ */

function relativeTime(timestamp) {

    if (!timestamp) {
        return "-";
    }

    const date =
        new Date(timestamp);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return formatTime(timestamp);
    }

    const seconds =
        Math.floor(
            (Date.now() - date.getTime()) / 1000
        );


    if (seconds < 5) {
        return "just now";
    }

    if (seconds < 60) {
        return `${seconds}s ago`;
    }


    const minutes =
        Math.floor(seconds / 60);


    if (minutes < 60) {
        return `${minutes}m ago`;
    }


    const hours =
        Math.floor(minutes / 60);


    return `${hours}h ago`;
}


/* ============================================================
   SYSTEM STATUS
   ============================================================ */

function setSystemStatus(
    online,
    message
) {

    const dot =
        $("statusDot");

    const text =
        $("statusText");


    if (!dot || !text) {
        return;
    }


    text.textContent =
        message;


    dot.classList.toggle(
        "error",
        !online
    );
}


/* ============================================================
   ERROR
   ============================================================ */

function showError(message) {

    const banner =
        $("errorBanner");


    if (!banner) {
        return;
    }


    banner.textContent =
        message;


    banner.classList.add(
        "visible"
    );
}


function hideError() {

    const banner =
        $("errorBanner");


    if (!banner) {
        return;
    }


    banner.classList.remove(
        "visible"
    );
}


/* ============================================================
   SUMMARY METRICS
   ============================================================ */

function renderMetrics(data) {

    const malicious =
        number(
            data.malicious_requests_detected
        );


    const rateBlocks =
        number(
            data.rate_limit_blocks
        );


    const allowed =
        number(
            data.allowed_requests
        );


    const blocked =
        number(
            data.blocked_requests
        );


    const total =
        number(
            data.total_events
        );


    $("malicious").textContent =
        malicious.toLocaleString();


    $("rateBlocks").textContent =
        rateBlocks.toLocaleString();


    $("allowed").textContent =
        allowed.toLocaleString();


    $("blocked").textContent =
        blocked.toLocaleString();


    $("total").textContent =
        total.toLocaleString();


    $("activityTotal").textContent =
        total.toLocaleString();


    $("activityThreats").textContent =
        malicious.toLocaleString();


    $("activityBlocked").textContent =
        blocked.toLocaleString();


    $("eventCount").textContent =
        `${total.toLocaleString()} events`;
}


/* ============================================================
   ATTACK DISTRIBUTION
   ============================================================ */

function renderDistribution(data) {

    const container =
        $("distributionList");


    const distribution =
        data.category_distribution || {};


    const entries =
        Object.entries(
            distribution
        );


    if (
        entries.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">
                No attack categories detected.
            </div>
        `;

        return;
    }


    entries.sort(
        (a, b) =>
            number(b[1]) -
            number(a[1])
    );


    const maximum =
        Math.max(
            ...entries.map(
                item => number(item[1])
            ),
            1
        );


    container.innerHTML =
        entries
            .slice(0, 8)
            .map(
                ([category, count]) => {

                    const percentage =
                        (
                            number(count) /
                            maximum
                        ) * 100;


                    return `
                        <div class="distribution-row">

                            <div
                                class="distribution-name"
                                title="${escapeHtml(category)}"
                            >
                                ${escapeHtml(category)}
                            </div>

                            <div class="progress">
                                <div
                                    class="progress-fill"
                                    style="width:${percentage}%"
                                ></div>
                            </div>

                            <div class="distribution-count">
                                ${number(count)}
                            </div>

                        </div>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   SEVERITY
   ============================================================ */

function normalizeSeverity(
    severity
) {

    if (!severity) {
        return "unknown";
    }

    return String(
        severity
    ).toLowerCase();
}


function severityBadge(
    severity
) {

    const normalized =
        normalizeSeverity(
            severity
        );


    if (
        normalized === "critical"
    ) {

        return `
            <span class="badge badge-critical">
                CRITICAL
            </span>
        `;
    }


    if (
        normalized === "high"
    ) {

        return `
            <span class="badge badge-high">
                HIGH
            </span>
        `;
    }


    if (
        normalized === "medium"
    ) {

        return `
            <span class="badge badge-medium">
                MEDIUM
            </span>
        `;
    }


    if (
        normalized === "low"
    ) {

        return `
            <span class="badge badge-low">
                LOW
            </span>
        `;
    }


    return `
        <span class="badge badge-neutral">
            UNKNOWN
        </span>
    `;
}


/* ============================================================
   DECISION
   ============================================================ */

function decisionBadge(
    decision
) {

    if (!decision) {

        return `
            <span class="badge badge-neutral">
                UNKNOWN
            </span>
        `;
    }


    const value =
        String(
            decision
        );


    const lower =
        value.toLowerCase();


    if (
        lower.includes("block") ||
        lower.includes("deny")
    ) {

        return `
            <span class="badge badge-blocked">
                ${escapeHtml(value)}
            </span>
        `;
    }


    return `
        <span class="badge badge-allowed">
            ${escapeHtml(value)}
        </span>
    `;
}


/* ============================================================
   RECENT SECURITY ALERTS
   ============================================================ */

function renderAlerts(data) {

    const container =
        $("alertList");


    const events =
        Array.isArray(
            data.recent_events
        )
            ? data.recent_events
            : [];


    const alerts =
        events
            .filter(
                event => {

                    const decision =
                        String(
                            event.decision ||
                            event.action ||
                            ""
                        ).toLowerCase();


                    const severity =
                        String(
                            event.severity ||
                            ""
                        ).toLowerCase();


                    return (
                        decision.includes("block") ||
                        decision.includes("deny") ||
                        severity === "critical" ||
                        severity === "high"
                    );
                }
            )
            .slice(0, 8);


    if (
        alerts.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">

                <strong>
                    No active security alerts
                </strong>

                SentinelShield is monitoring
                incoming traffic.

            </div>
        `;

        return;
    }


    container.innerHTML =
        alerts
            .map(
                event => {

                    const severity =
                        normalizeSeverity(
                            event.severity
                        );


                    const category =
                        event.category ||
                        event.attack_category ||
                        event.threat_category ||
                        "Security Event";


                    const path =
                        event.path ||
                        event.url ||
                        "/";


                    const ip =
                        event.ip ||
                        event.client_ip ||
                        "Unknown";


                    return `
                        <div class="alert-item">

                            <span
                                class="severity-dot ${escapeHtml(severity)}"
                            ></span>

                            <div class="alert-main">

                                <div class="alert-title">
                                    ${escapeHtml(category)}
                                </div>

                                <div class="alert-details">

                                    <span>
                                        ${escapeHtml(ip)}
                                    </span>

                                    <span>
                                        ${escapeHtml(path)}
                                    </span>

                                </div>

                            </div>

                            <div class="alert-time">
                                ${escapeHtml(
                                    relativeTime(
                                        event.timestamp
                                    )
                                )}
                            </div>

                        </div>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   REPEATED SOURCE IPs
   ============================================================ */

function renderSources(data) {

    const container =
        $("sourceList");


    const sources =
        Array.isArray(
            data.repeatedly_flagged_ips
        )
            ? data.repeatedly_flagged_ips
            : [];


    if (
        sources.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">
                No repeatedly flagged sources.
            </div>
        `;

        return;
    }


    container.innerHTML =
        sources
            .slice(0, 10)
            .map(
                item => {

                    const ip =
                        item.ip ||
                        item.client_ip ||
                        "Unknown";


                    const count =
                        number(
                            item.count ||
                            item.events ||
                            item.total
                        );


                    return `
                        <div class="source-item">

                            <div class="source-ip">
                                ${escapeHtml(ip)}
                            </div>

                            <div class="source-events">
                                ${count} events
                            </div>

                            <div class="source-status">

                                <span
                                    class="badge badge-blocked"
                                >
                                    FLAGGED
                                </span>

                            </div>

                        </div>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   RECENT EVENTS TABLE
   ============================================================ */

function renderEvents(data) {

    const table =
        $("eventsTable");


    const events =
        Array.isArray(
            data.recent_events
        )
            ? data.recent_events
            : [];


    if (
        events.length === 0
    ) {

        table.innerHTML = `
            <tr>

                <td colspan="7">

                    <div class="empty-state">

                        <strong>
                            No security events
                        </strong>

                        Waiting for incoming
                        telemetry.

                    </div>

                </td>

            </tr>
        `;

        return;
    }


    table.innerHTML =
        events
            .slice(0, 30)
            .map(
                event => {

                    const timestamp =
                        event.timestamp ||
                        event.time ||
                        "";


                    const ip =
                        event.ip ||
                        event.client_ip ||
                        "-";


                    const method =
                        event.method ||
                        "-";


                    const path =
                        event.path ||
                        event.url ||
                        "/";


                    const category =
                        event.category ||
                        event.attack_category ||
                        event.threat_category ||
                        "Normal Traffic";


                    const severity =
                        event.severity ||
                        "";


                    const decision =
                        event.decision ||
                        event.action ||
                        "ALLOWED";


                    return `
                        <tr>

                            <td class="timestamp">
                                ${escapeHtml(
                                    formatTime(
                                        timestamp
                                    )
                                )}
                            </td>

                            <td>
                                <span class="ip-text">
                                    ${escapeHtml(ip)}
                                </span>
                            </td>

                            <td>
                                <span class="method">
                                    ${escapeHtml(method)}
                                </span>
                            </td>

                            <td>

                                <span
                                    class="path-text"
                                    title="${escapeHtml(path)}"
                                >
                                    ${escapeHtml(path)}
                                </span>

                            </td>

                            <td>
                                ${escapeHtml(category)}
                            </td>

                            <td>
                                ${severityBadge(
                                    severity
                                )}
                            </td>

                            <td>
                                ${decisionBadge(
                                    decision
                                )}
                            </td>

                        </tr>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   ACTIVITY VISUALIZATION
   ============================================================
   This is deliberately based on recent event timestamps.
   It does NOT fabricate telemetry.
   ============================================================ */

function renderActivity(data) {

    const container =
        $("activityChart");


    const events =
        Array.isArray(
            data.recent_events
        )
            ? data.recent_events
            : [];


    if (
        events.length === 0
    ) {

        container.innerHTML = `
            <div class="chart-empty">
                Waiting for telemetry...
            </div>
        `;

        return;
    }


    /*
     * Create 20 buckets.
     *
     * Each event is placed into a bucket based on its
     * timestamp. If timestamp parsing is unavailable,
     * events are distributed according to their returned
     * order rather than inventing numerical traffic data.
     */

    const buckets =
        new Array(20).fill(0);


    let validTimestamps = 0;


    const now =
        Date.now();


    events.forEach(
        event => {

            const timestamp =
                event.timestamp ||
                event.time;


            if (!timestamp) {
                return;
            }


            const date =
                new Date(timestamp);


            if (
                Number.isNaN(
                    date.getTime()
                )
            ) {
                return;
            }


            const age =
                now -
                date.getTime();


            const bucket =
                Math.floor(
                    age /
                    (
                        5 *
                        60 *
                        1000
                    )
                );


            if (
                bucket >= 0 &&
                bucket < 20
            ) {

                buckets[
                    19 - bucket
                ]++;

                validTimestamps++;
            }
        }
    );


    if (
        validTimestamps === 0
    ) {

        /*
         * We have events, but no usable timestamps.
         * Show a neutral activity representation rather
         * than pretending the chart contains real rates.
         */

        container.innerHTML = `
            <div class="chart-empty">
                Event timestamps unavailable.
            </div>
        `;

        return;
    }


    const maximum =
        Math.max(
            ...buckets,
            1
        );


    const bars =
        buckets
            .map(
                value => {

                    const height =
                        Math.max(
                            3,
                            (
                                value /
                                maximum
                            ) * 100
                        );


                    return `
                        <div
                            class="chart-bar"
                            style="height:${height}%"
                            title="${value} event(s)"
                        ></div>
                    `;
                }
            )
            .join("");


    container.innerHTML = `
        <div class="chart-bars">
            ${bars}
        </div>
    `;
}


/* ============================================================
   LAST UPDATE
   ============================================================ */

function updateLastUpdate() {

    const now =
        new Date();


    const value =
        now.toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        );


    $("topLastUpdate").textContent =
        `Last telemetry: ${value}`;


    $("activityMeta").textContent =
        `Updated ${value}`;
}


/* ============================================================
   FETCH API
   ============================================================ */

async function fetchDashboard() {

    try {

        const response =
            await fetch(
                SUMMARY_ENDPOINT,
                {
                    method: "GET",

                    credentials:
                        "same-origin",

                    cache:
                        "no-store",

                    headers: {
                        "Accept":
                            "application/json"
                    }
                }
            );


        if (
            response.status === 401
        ) {

            throw new Error(
                "Dashboard authentication required."
            );
        }


        if (
            response.status === 403
        ) {

            throw new Error(
                "Dashboard API access denied."
            );
        }


        if (
            !response.ok
        ) {

            throw new Error(
                `Dashboard API returned HTTP ${response.status}.`
            );
        }


        const data =
            await response.json();


        /*
         * Render all dashboard components.
         */

        renderMetrics(data);

        renderDistribution(data);

        renderAlerts(data);

        renderSources(data);

        renderEvents(data);

        renderActivity(data);

        updateLastUpdate();


        /*
         * Backend successfully responded.
         */

        hideError();


        setSystemStatus(
            true,
            "SYSTEM OPERATIONAL"
        );


        console.log(
            "SentinelShield telemetry updated."
        );


    } catch (error) {

        console.error(
            "SentinelShield dashboard error:",
            error
        );


        setSystemStatus(
            false,
            "TELEMETRY UNAVAILABLE"
        );


        showError(
            error.message ||
            "Unable to retrieve dashboard telemetry."
        );
    }
}


/* ============================================================
   INITIALIZATION
   ============================================================ */

function initializeDashboard() {

    console.log(
        "SentinelShield SOC Console initialized."
    );


    /*
     * Initial load.
     */

    fetchDashboard();


    /*
     * Continuous monitoring.
     */

    window.setInterval(
        fetchDashboard,
        REFRESH_INTERVAL
    );
}


/* ============================================================
   START
   ============================================================ */

if (
    document.readyState ===
    "loading"
) {

    document.addEventListener(
        "DOMContentLoaded",
        initializeDashboard
    );

} else {

    initializeDashboard();
}
