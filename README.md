# NETSENTRY — Network Security Assessment

Educational network security assessment project with a Flask dashboard.

## Safety
- Public demo mode uses synthetic sample data only.
- Live scan and host discovery endpoints are disabled when `DEMO_ONLY=1`.
- Local scanning is restricted to authorized loopback/private IPv4 lab targets.
- No exploitation, password guessing, or brute-force actions are performed.

## Source package
The prepared project source is packaged as `NetworkPentestTool_PublicDemo.zip`. Extract the contents of its `network-pentest-tool/` folder into the repository root so `web_app.py`, `web_scanner.py`, `templates/`, `static/`, and `requirements.txt` are at the top level.
