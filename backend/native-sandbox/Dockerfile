# H2 offline-compatibility test image only. Ruby 3.2 reached EOL in March 2026.
# Never deploy this legacy-runtime image or expose a native HTTP endpoint.
# Exact upstream platform image digest and lockfile are intentionally pinned.
FROM ruby:3.2.11-bookworm@sha256:bf13a46a498fb4055d0e52495c351a2648c8bc8d41b473ee3f734041a74c7f56

ENV BUNDLE_GEMFILE=/opt/native/Gemfile \
    BUNDLE_FROZEN=true \
    BUNDLE_PATH=/usr/local/bundle
WORKDIR /opt/native
COPY Gemfile Gemfile.lock ./
RUN gem install bundler --version 4.0.22 --no-document \
    && bundle _4.0.22_ install --jobs 2 --retry 2 \
    && ruby -e "raise 'wrong Ruby runtime' unless RUBY_VERSION == '3.2.11'; require 'bundler/setup'; require 'fluent/plugin/parser'; raise 'wrong Fluentd' unless Gem.loaded_specs.fetch('fluentd').version.to_s == '1.17.1'"
COPY test_native/project_native_runner.rb ./project_native_runner.rb
RUN chmod 0444 Gemfile Gemfile.lock project_native_runner.rb
USER 65532:65532
ENTRYPOINT ["ruby","-rbundler/setup","/opt/native/project_native_runner.rb"]
