require "helper"

describe Fog::Bouncer::Security do
  before do
    Fog::Bouncer.reset
    Fog::Mock.reset if Fog.mocking?

    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]
    @doorlist.import_remote_groups
    @fog = Fog::Bouncer.fog
  end

  describe "#sync" do
    before do
      @doorlist.sync
    end

    it "synchronises against AWS" do
      @fog.security_groups.size.must_equal 4

      fog_douchebag = @fog.security_groups.get('douchebag')
      douchebag = @doorlist.groups.find { |g| g.name == 'douchebag' }
      douchebag.remote.group_id.must_equal fog_douchebag.group_id

      source = @doorlist.groups.find { |g| g.name == 'guido' }.sources.first
      assert source.remote # not sure of the minitest/spec equivalent
      source.user_alias.must_equal "jersey_shore"
      source.user_id.must_equal ENV['AWS_ACCOUNT_ID']

      default = @fog.security_groups.get('default')
      default.ip_permissions.must_be_empty

      @doorlist.clear_remote
    end
  end

  describe "#extra_remote_groups" do
    it "detects the extra groups" do
      @doorlist.extra_remote_groups.must_equal [@doorlist.groups.find { |g| g.name == "default"}]

      @doorlist.clear_remote
    end
  end

  describe "#missing_remote_groups" do
    before do
      @doorlist.sync
      @new = Fog::Bouncer::Group.new('new', 'new', self)
      @new.local = true
      @doorlist.groups << @new
    end

    it "detects the missing groups" do
      @doorlist.missing_remote_groups.must_equal [@new]

      @doorlist.clear_remote
    end
  end
end
