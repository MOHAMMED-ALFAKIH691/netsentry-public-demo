# NETSENTRY — Network Penetration Testing Tool

An educational network security assessment project with a Flask dashboard. The local version supports authorized private IPv4 lab scanning with Nmap, lightweight service detection, optional NVD keyword lookup, heuristic exposure scoring, authentication-exposure simulation (no credentials are tested), and JSON reports.

## Safety modes

- **Local mode (`DEMO_ONLY=0`, the default):** live scanning is limited in code to IPv4 loopback and private IPv4 addresses. Host discovery is limited to a maximum of 256 addresses. Use only systems and networks you own or are explicitly authorized to assess.
- **Public demo mode (`DEMO_ONLY=1`):** disables both live scan endpoints. Visitors can load synthetic sample data and download a demo report. This is the only supported mode for public hosting.
- No exploitation, password guessing, brute-force attempts, or destructive actions are performed.
- NVD keyword matches are leads for manual validation, not proof that a target is vulnerable.

## Local setup

See `README_AR.md` for Windows/VS Code and Kali instructions.

## Public deployment on Render

This repository includes `render.yaml` for a demo-only Render Web Service. Upload the contents of this folder to a GitHub repository, then create a Blueprint at https://dashboard.render.com/blueprints/new. Render reads the configuration and sets `DEMO_ONLY=1` automatically.

Never set `DEMO_ONLY=0` on a public deployment. The public build does not install or need Nmap. The live scanner is for local, authorized lab use only.

See `README_DEPLOY_AR.md` for step-by-step Arabic instructions.
