# CI ONLY. Ruby 3.2 reached EOL 2026-03-27; never deploy this legacy profile.
# Exact official Ruby 3.2.11 multiarch OCI digest and locked Fluentd bundle.
# The test runner executes a fixed synthetic parser offline as UID 65532.
# This image is NOT a public service or user parser execution endpoint.
FROM ruby:3.2.11-slim-bookworm@sha256:84140472007d27c7ec641dbc606a47ff9c0aa5f358445947b7350392fa5115e5 AS bundle
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/parserstudio
COPY backend/Gemfile backend/Gemfile.lock ./
ENV BUNDLE_GEMFILE=/opt/parserstudio/Gemfile
RUN ruby -e "abort 'WRONG_RUBY' unless RUBY_VERSION == '3.2.11'" && \
    gem install bundler -v 4.0.22 --no-document && \
    bundle config set --local frozen true && bundle install --jobs=2 --retry=2

FROM ruby:3.2.11-slim-bookworm@sha256:84140472007d27c7ec641dbc606a47ff9c0aa5f358445947b7350392fa5115e5
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
