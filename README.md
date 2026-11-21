# TCDC Blue Team Toolkit — practice edition

Five read-only checks in one Python 3.10+ standard-library script. **Not approved for tournament use.** The TCDC packet requires public repository submission/review for custom tools (R20) and prohibits AI usage (R21). Obtain explicit Black Team authorization before using this AI-generated toolkit in competition. Use on your own lab in the meantime.

## Setup (Windows PowerShell or Linux)

```powershell
python blue_monitor.py health
python blue_monitor.py auth
python blue_monitor.py users
python blue_monitor.py integrity --init-baseline
python blue_monitor.py integrity
python blue_monitor.py ports --init-baseline
python blue_monitor.py ports
```

On Windows, `py -3 blue_monitor.py health` may work if `python` isn't recognized.

**Configure first:** edit `config.json`. All default service targets are `127.0.0.1` to avoid touching competition infrastructure. Only set addresses for systems you own or have permission to test. For web apps, specify an optional `url` with a known safe endpoint. Change `auth_logs` and `watch_files` to valid local paths. Run from a folder where you can write baseline JSON files. On Linux, reading sensitive logs or files may require elevated permissions; use least privilege.

## Modules

- `health`: SSH/FTP banner checks, HTTP response status, DNS UDP A query, TCP reachability for MQTT. **MQTT TCP success is not proof of broker functionality.** Health probes can be logged by remote services; only use authorized endpoints.
- `auth`: counts matching failure messages in the most recent lines of configured text log files; **not** a full authentication detector or time-based correlation. Windows Event Logs and systemd journal aren't read directly.
- `integrity`: creates a SHA-256 baseline of configured files/directories, then reports added/removed/modified paths. Store baselines securely and only initialize after verifying files are known-good. It refuses to overwrite an existing baseline.
- `users`: inventories local accounts and privileged group output. On Windows it uses `net user` and `net localgroup Administrators`. Does not audit domain accounts.
- `ports`: compares `ss -lntup` (Linux) or `netstat -ano -p tcp` (Windows) output against a baseline. PID changes and formatting can generate noise. It doesn't scan remote machines.

## Important limitations

This toolkit is **not** a background daemon, SIEM, or replacement for Fail2ban. Run checks manually; no blocking, automatic remediation, password changes, or outbound alert delivery. It does not touch Wazuh or auditd. The DNS check requires an answer with no DNS error, which may be inappropriate for some DNS configurations. Port checks may show partial process information without sufficient privileges. `auth` cannot detect all attack patterns. Investigate findings manually and confirm scored services work after any changes.

## Suggested safe lab exercise

1. Edit `config.json` to point to your own VM's services.
2. Run `health` and observe reachable/unreachable results.
3. Create `integrity` and `ports` baselines after verifying your lab is in a clean state.
4. Make a harmless change to a watched test file, then run `integrity` again.
5. Restore the file and compare results. Do not use this on tournament infrastructure before the authorized period or without approval.
