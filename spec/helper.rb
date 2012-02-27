require "minitest/autorun"

ENV['AWS_ACCESS_KEY_ID'] ||= "abcde1234"
ENV['AWS_SECRET_ACCESS_KEY'] ||= "abcde1234"

require "fog/bouncer"

Fog.mock! unless ENV['FOG_REAL']
