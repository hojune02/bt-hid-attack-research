FROM bt-attack-base

# InternalBlue — Mode B (Broadcom only).  PyPI build fails on arm64;
# install from git HEAD which has the fix.  The || true keeps the build
# passing on amd64 if the install succeeds via PyPI in the base image.
RUN pip3 install --no-cache-dir \
    "git+https://github.com/seemoo-lab/internalblue.git#egg=internalblue" \
    || pip3 install --no-cache-dir internalblue \
    || true

COPY knob_mitm.py    /attack/knob_mitm.py
COPY knob_mode_b.py  /attack/knob_mode_b.py
WORKDIR /attack

# Default: show Mode A help.  Override with:
#   docker compose run knob python3 knob_mode_b.py --check-chip
CMD ["python3", "knob_mitm.py", "--help"]
