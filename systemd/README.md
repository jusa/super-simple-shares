# systemd

`run-gunicorn.sh` reads `host` and `port` from the config file `[server]` section and starts gunicorn with that bind address, so you only need to change `config.ini` when changing port or host.

Copy `super-simple-shares.service` to `/etc/systemd/system/`, edit the unit to set `WorkingDirectory`, `Environment` (FILE_SHARE_CONFIG), and `ExecStart` to your install path (replace `/opt/super-simple-shares`). Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable super-simple-shares
sudo systemctl start super-simple-shares
```

Ensure the `User`/`Group` can read the app and config and write the database.
