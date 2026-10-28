import sys

from . import config, internal, store
from .app import create_app


def main():
    host = config.check_host()
    port = config.get_port()
    store.ensure_ready()
    try:
        internal.start(port)
    except OSError as exc:
        sys.exit(f"refusing to start: cannot bind {host}:{port + 1} ({exc})")
    app = create_app()
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
