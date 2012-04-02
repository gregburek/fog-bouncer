require "helper"

describe Fog::Bouncer::Security do
  before do
    Fog::Bouncer.reset
    Fog::Mock.reset if Fog.mocking?

    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]

    @fog = Fog::Bouncer.fog

  end

  describe "#sync" do
    before do
      @doorlist.sync
    end

    it "synchronises against AWS" do
      @fog.security_groups.size.must_equal 3

      fog_douchebag = @fog.security_groups.get('douchebag')
      douchebag = @doorlist.groups.find { |g| g.name == 'douchebag' }
      douchebag.remote.group_id.must_equal fog_douchebag.group_id

      source = @doorlist.groups.find { |g| g.name == 'guido' }.sources.first
      assert source.remote # not sure of the minitest/spec equivalent
      source.user_alias.must_equal "jersey_shore"
      source.user_id.must_equal ENV['AWS_ACCOUNT_ID']

      default = @fog.security_groups.get('default')
      default.ip_permissions.must_be_empty
    end
  end

  describe "#extras" do
    before do
      @extras = @doorlist.extras
      @default = @doorlist.groups.find { |g| g.name == "default" }
    end

    it "detects the extra groups" do
      @extras.must_equal [@default]
    end
  end

  describe "#missing" do
    before do
      @douchebag = @doorlist.groups.find { |g| g.name == 'douchebag' }
      @douchebag.sync
      @guido = @doorlist.groups.find { |g| g.name == 'guido' }
      @default = @doorlist.groups.find { |g| g.name == 'default' }
    end

    it "detects the missing groups" do
      @doorlist.missing.must_equal [@guido]
    end

    it "detects groups with missing sources" do
      source = Fog::Bouncer::Sources.for("2.2.2.2/2", @douchebag)
      source.protocols << Fog::Bouncer::Protocols::TCP.new(90, source)
      @douchebag.sources << source
      @doorlist.missing.must_equal [@douchebag, @guido]
    end
  end
end
