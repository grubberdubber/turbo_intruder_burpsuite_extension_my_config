# Turbo Intruder — Race Condition Lab Runner v2.0
#
# Designed for authorized local/containerized labs.
#
# Features:
#   - Burst matrix: 10 / 20 / 30 / 40 / 50 requests
#   - Multiple independent trials per burst size
#   - HTTP/2 single-packet attack using BURP2 + gates
#   - Per-trial labels for reliable response attribution
#   - Warmup separated from experiment statistics
#   - Trial success rate
#   - Response success rate
#   - HTTP status distribution
#   - Response timing statistics
#   - Response ordering
#   - Final experiment summary
#
# IMPORTANT:
#   You MUST customize is_success() for the specific lab.
#   HTTP 200 alone is NOT automatically considered a race success.


# ============================================================
# CONFIGURATION
# ============================================================

BURST_SIZES = [10, 20, 30, 40, 50]

TRIALS_PER_SIZE = 10

# Delay between independent trials.
# This separates experiments; it is NOT part of synchronization.
BETWEEN_TRIALS = 0.15

# Send one warmup request before the actual experiment.
WARMUP_ENABLED = True

# Reuse one value across the entire burst?
#
# True:
#   Every request in a burst uses the same generated token.
#
# False:
#   Every request receives a different token.
#
# Choose according to the lab's semantics.
SAME_PAYLOAD = True

TOKEN_LENGTH = 12

# Placeholder used in the request copied from Burp.
#
# Example request:
#
# POST /redeem HTTP/2
# ...
#
# code=RACE_CONDITION
#
# The script replaces RACE_CONDITION.
MARKER = "RACE_CONDITION"


# ============================================================
# ENGINE CONFIGURATION
# ============================================================

# BURP2 + one connection is the Turbo Intruder pattern used
# for HTTP/2 single-packet race testing.
CONCURRENT_CONNECTIONS = 1

# BURP2 manages connection reuse itself.
# This value is intentionally conservative/documentary.
REQUESTS_PER_CONNECTION = 100


# ============================================================
# EXPERIMENT STATE
# ============================================================

# Number of actual experiment requests expected.
EXPECTED_EXPERIMENT_RESPONSES = (
    sum(BURST_SIZES) * TRIALS_PER_SIZE
)

# Number of experiment responses processed.
experiment_responses = 0

# Prevent the final report from being printed twice.
report_printed = False


# Structure:
#
# results[size][trial] = {
#     "expected": int,
#     "received": int,
#     "success": int,
#     "statuses": {},
#     "times": [],
#     "orders": []
# }
#
results = {}


# ============================================================
# HELPERS
# ============================================================

def random_token(length=TOKEN_LENGTH):
    """
    Generate a simple alphanumeric token.

    Turbo Intruder also provides payload helpers such as
    $randomplz, but generating the value here makes the
    experiment state explicit and reproducible.
    """

    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
    )

    return "".join(
        alphabet[__import__("random").randint(0, len(alphabet) - 1)]
        for _ in range(length)
    )


def parse_label(label):
    """
    Parse:

        race:size=20:trial=3

    into:

        (20, 3)

    Returns None for non-experiment requests.
    """

    if not label:
        return None

    prefix = "race:size="

    if not label.startswith(prefix):
        return None

    try:
        remainder = label[len(prefix):]

        size_text, trial_text = remainder.split(":trial=")

        return int(size_text), int(trial_text)

    except Exception:
        return None


def initialize_results():
    """
    Build the experiment matrix before sending requests.
    """

    for size in BURST_SIZES:

        results[size] = {}

        for trial in range(1, TRIALS_PER_SIZE + 1):

            results[size][trial] = {
                "expected": size,
                "received": 0,
                "success": 0,
                "statuses": {},
                "times": [],
                "orders": []
            }


def is_success(req):
    """
    ============================================================
    LAB-SPECIFIC SUCCESS DETECTOR
    ============================================================

    THIS IS THE ONLY PART YOU SHOULD NORMALLY CHANGE.

    Do NOT assume:

        HTTP 200 == race success

    A race-condition lab may instead indicate success using:

        - a different status code
        - a response body marker
        - a changed balance
        - a duplicated object
        - a successful redirect
        - a different JSON field
        - a particular error disappearing
        - some second-order effect

    Example:

        return req.status == 302

    Or:

        return "already redeemed" not in req.response

    Or:

        return '"success":true' in req.response

    Replace the example below with the actual oracle
    for your Docker lab.
    """

    SUCCESS_STATUS_CODES = []

    SUCCESS_MARKERS = [
        # "SUCCESS",
        # "race-won",
        # '"success":true',
    ]

    if req.status in SUCCESS_STATUS_CODES:
        return True

    response = req.response or ""

    for marker in SUCCESS_MARKERS:

        if marker in response:
            return True

    return False


def record_result(req, size, trial):
    """
    Record one experiment response.
    """

    global experiment_responses

    if size not in results:
        return

    if trial not in results[size]:
        return

    trial_data = results[size][trial]

    trial_data["received"] += 1

    if is_success(req):
        trial_data["success"] += 1

    status = req.status

    if status not in trial_data["statuses"]:
        trial_data["statuses"][status] = 0

    trial_data["statuses"][status] += 1

    # Turbo Intruder exposes response time in microseconds.
    trial_data["times"].append(req.time)

    # req.order is the response order within the gate.
    trial_data["orders"].append(req.order)

    experiment_responses += 1


def average(values):
    if not values:
        return 0

    return sum(values) / float(len(values))


def min_value(values):
    if not values:
        return 0

    return min(values)


def max_value(values):
    if not values:
        return 0

    return max(values)


# ============================================================
# REPORTING
# ============================================================

def report_trial(size, trial):
    """
    Print detailed information about one trial.
    """

    data = results[size][trial]

    expected = data["expected"]
    received = data["received"]
    success = data["success"]

    if expected:
        response_rate = (
            float(received) / expected
        ) * 100.0
    else:
        response_rate = 0

    times = data["times"]

    print(
        "[trial] "
        "size=%d "
        "trial=%d "
        "received=%d/%d "
        "success=%d "
        "response_rate=%.1f%% "
        "min=%dus "
        "avg=%.0fus "
        "max=%dus"
        % (
            size,
            trial,
            received,
            expected,
            success,
            response_rate,
            min_value(times),
            average(times),
            max_value(times)
        )
    )


def report_summary():
    """
    Print the complete experiment report.
    """

    global report_printed

    if report_printed:
        return

    report_printed = True

    print("")
    print("=" * 72)
    print("RACE CONDITION LAB — EXPERIMENT SUMMARY")
    print("=" * 72)

    print(
        "Expected experiment responses: %d"
        % EXPECTED_EXPERIMENT_RESPONSES
    )

    print(
        "Received experiment responses: %d"
        % experiment_responses
    )

    print("")

    for size in BURST_SIZES:

        trial_successes = 0
        total_success_responses = 0
        total_responses = 0

        all_times = []

        print("-" * 72)
        print("BURST SIZE: %d" % size)

        for trial in range(1, TRIALS_PER_SIZE + 1):

            data = results[size][trial]

            received = data["received"]
            success = data["success"]

            total_responses += received
            total_success_responses += success

            all_times.extend(data["times"])

            # A trial is considered successful if at least
            # one response satisfies the lab-specific oracle.
            if success > 0:
                trial_successes += 1

            report_trial(size, trial)

        trial_rate = (
            float(trial_successes) / TRIALS_PER_SIZE
        ) * 100.0

        response_rate = (
            float(total_success_responses) / total_responses
        ) * 100.0 if total_responses else 0

        print("")
        print(
            "Trial success rate: %.1f%% (%d/%d)"
            % (
                trial_rate,
                trial_successes,
                TRIALS_PER_SIZE
            )
        )

        print(
            "Response success rate: %.1f%% (%d/%d)"
            % (
                response_rate,
                total_success_responses,
                total_responses
            )
        )

        print(
            "Timing: min=%dus avg=%.0fus max=%dus"
            % (
                min_value(all_times),
                average(all_times),
                max_value(all_times)
            )
        )

    print("")
    print("=" * 72)
    print("EXPERIMENT COMPLETE")
    print("=" * 72)


# ============================================================
# QUEUE REQUESTS
# ============================================================

def queueRequests(target, wordlists):

    global results

    initialize_results()

    engine = RequestEngine(
        endpoint=target.endpoint,

        # HTTP/2 single-packet engine.
        engine=Engine.BURP2,

        # Required pattern for the single-packet technique.
        concurrentConnections=CONCURRENT_CONNECTIONS,

        requestsPerConnection=REQUESTS_PER_CONNECTION
    )

    # Keep state attached to the engine.
    engine.userState["experiment"] = {
        "expected": EXPECTED_EXPERIMENT_RESPONSES,
        "warmup": WARMUP_ENABLED
    }


    # --------------------------------------------------------
    # WARMUP
    # --------------------------------------------------------

    if WARMUP_ENABLED:

        engine.queue(
            target.req,
            label="warmup"
        )

        engine.openGate("warmup")


    # --------------------------------------------------------
    # EXPERIMENT MATRIX
    # --------------------------------------------------------

    for burst_size in BURST_SIZES:

        for trial in range(1, TRIALS_PER_SIZE + 1):

            gate_name = (
                "race-size-%d-trial-%d"
                % (burst_size, trial)
            )

            label = (
                "race:size=%d:trial=%d"
                % (burst_size, trial)
            )


            # ------------------------------------------------
            # PAYLOAD
            # ------------------------------------------------

            shared_token = None

            if SAME_PAYLOAD:

                shared_token = random_token()


            # ------------------------------------------------
            # QUEUE BURST
            # ------------------------------------------------

            for request_number in range(burst_size):

                if SAME_PAYLOAD:

                    token = shared_token

                else:

                    token = random_token()


                request = target.req.replace(
                    MARKER,
                    token
                )


                engine.queue(
                    request,
                    gate=gate_name,
                    label=label
                )


            # ------------------------------------------------
            # RELEASE BURST
            # ------------------------------------------------

            engine.openGate(gate_name)


            # ------------------------------------------------
            # SEPARATE INDEPENDENT TRIALS
            # ------------------------------------------------

            if BETWEEN_TRIALS > 0:

                __import__("time").sleep(
                    BETWEEN_TRIALS
                )


# ============================================================
# RESPONSE HANDLER
# ============================================================

def handleResponse(req, interesting):

    # Always expose responses in Turbo Intruder.
    table.add(req)


    # Warmup is intentionally excluded from experiment metrics.
    if req.label == "warmup":

        return


    parsed = parse_label(req.label)

    if parsed is None:

        return


    size, trial = parsed

    record_result(
        req,
        size,
        trial
    )


    # --------------------------------------------------------
    # COMPLETION CHECK
    # --------------------------------------------------------

    if experiment_responses >= EXPECTED_EXPERIMENT_RESPONSES:

        report_summary()
