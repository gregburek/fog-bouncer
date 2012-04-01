require 'minitest/autorun'

ENV['AWS_ACCESS_KEY_ID'] ||= "abcde1234"
ENV['AWS_SECRET_ACCESS_KEY'] ||= "abcde1234"
ENV['AWS_ACCOUNT_ID'] ||= "1234567890"

require "fog/bouncer"

Scrolls::Log.start(File.open(File.dirname(__FILE__) + '/../logs/test.log', 'w'))

def load_security(security)
  Fog::Bouncer.load File.dirname(__FILE__) + "/support/security/#{security}.rb"
end

Fog.mock! unless ENV['FOG_REAL']

MiniTest::Unit.after_tests do
  Fog::Bouncer.doorlists.each do |name, doorlist|
    doorlist.remote_groups.each do |group|
      group.revoke
    end

    doorlist.remote_groups.each do |group|
      group.destroy
    end

    doorlist.reset!
  end
end

