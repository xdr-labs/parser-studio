# CI ONLY. The network-enabled build installs the exact locked Fluentd bundle.
# The test runner executes a fixed synthetic parser offline as UID 65532.
# This image is NOT a public service or user parser execution endpoint.
FROM ruby:3.2-slim-bookworm AS bundle
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/parserstudio
COPY backend/Gemfile backend/Gemfile.lock ./
ENV BUNDLE_GEMFILE=/opt/parserstudio/Gemfile
RUN gem install bundler -v 4.0.22 --no-document && \
    bundle config set --local frozen true && bundle install --jobs=2 --retry=2

FROM ruby:3.2-slim-bookworm
RUN groupadd --gid 65532 native && \
    useradd --uid 65532 --gid 65532 --home-dir /tmp --shell /usr/sbin/nologin native
COPY --from=bundle /usr/local/bundle /usr/local/bundle
WORKDIR /opt/parserstudio
COPY backend/Gemfile backend/Gemfile.lock ./
COPY backend/test_native/project_native_runner.rb ./project_native_runner.rb
ENV BUNDLE_GEMFILE=/opt/parserstudio/Gemfile \
    BUNDLE_FROZEN=true HOME=/tmp
USER 65532:65532
ENTRYPOINT ["ruby", "-rbundler/setup", "/opt/parserstudio/project_native_runner.rb"]
