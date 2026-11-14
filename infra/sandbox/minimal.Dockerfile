# The sandbox, without the scanners.
#
# The adversarial isolation test (ADR-009) tests the *boundary*, not the tools inside
# it: the same entrypoint, run under the same `docker_run_argv` profile, from the same
# single source of truth. What is being asserted is that DNS fails, that the root
# filesystem is read-only, that `unshare` returns EPERM — none of which has anything to
# do with which analysers are installed.
#
# So this image exists to keep that test **fast enough to run on every commit**. The
# full scanner image is four gigabytes and takes a quarter of an hour to build, and a
# boundary test that only runs nightly is a boundary test that finds the regression a
# day late. This one builds in seconds on top of a stock base.
#
# Point `BASTION_SANDBOX_TEST_IMAGE` at `bastion-sandbox:latest` to run the identical
# assertions against the real image. They pass there too; it just costs more.

FROM python:3.12-slim

COPY entrypoint.py /opt/bastion/entrypoint.py

RUN set -eux; \
    chmod 0755 /opt/bastion/entrypoint.py; \
    useradd --uid 65532 --create-home --home-dir /home/sandbox --shell /usr/sbin/nologin sandbox

USER 65532:65532

ENTRYPOINT ["python3", "/opt/bastion/entrypoint.py"]
