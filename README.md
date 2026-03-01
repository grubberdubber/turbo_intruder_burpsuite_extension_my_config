🚀 Universal HTTP/2 Race Sniper for Turbo Intruder

This script is designed for high-precision Race Condition testing using Burp Suite's Turbo Intruder. It leverages the Single-Packet Attack technique to synchronize multiple requests at the network level, bypassing standard rate limits and discovering logic flaws.
✨ Key Features

    Protocol Agnostic: Automatically handles HTTP/1.1 (Last-Byte Sync) and HTTP/2 (Single-Packet Attack) for maximum precision.

    WAF Evasion: Generates a unique hexadecimal token for each request to prevent caching and WAF blocking.

    Stealthy Injection: Uses a custom header (X-Race-Sync) to avoid interfering with the application's logic or JSON/XML schemas.

    Zero Dependencies: Compatible with the internal Jython engine (no ImportError: No module named secrets).

🛠️ How to Use

    Capture a Request: Send the target request (e.g., login, coupon redemption, or fund transfer) to Turbo Intruder.

    Add the Marker: Insert the word RACE_CONDITION into a header or a non-critical parameter.

        Example: X-Race-Sync: RACE_CONDITION

    Load the Script: Copy the Python script into the Turbo Intruder code editor.

    Execute: Click "Attack".

🔍 Analyzing Results

    The "Gate" Mechanism: The script queues all requests first, holding the final byte of each. Upon calling openGate(), it releases all requests simultaneously.

    Success Indicators: Look for multiple 200 OK responses where only one should be possible, or anomalies in the Length and Time columns.

⚠️ Disclaimer

This tool is for educational purposes and authorized security auditing only. Always obtain permission before testing.
