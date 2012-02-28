require "minitest/autorun"

ENV['AWS_ACCESS_KEY_ID'] ||= "abcde1234"
ENV['AWS_SECRET_ACCESS_KEY'] ||= "abcde1234"

require "fog/bouncer"

def load_security(security)
  Fog::Bouncer.load File.dirname(__FILE__) + "/support/security/#{security}.rb"
end

Fog.mock! unless ENV['FOG_REAL']
