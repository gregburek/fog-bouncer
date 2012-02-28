require "helper"

describe Fog::Bouncer::Security do
  before do
    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]

    @fog = Fog::Bouncer.fog

    Fog::Mock.reset if Fog.mocking?
  end

  describe "#sync" do
    before do
      @doorlist.sync
    end

    it "synchronises against AWS" do
      @fog.security_groups.size.must_equal 3

      fog_douchebag = @fog.security_groups.get('douchebag')
      douchebag = @doorlist.groups.find { |g| g.name == 'douchebag' }
      Fog::Bouncer::RemoteGroup.for(fog_douchebag.name, @doorlist).to_ip_permissions.must_equal douchebag.to_ip_permissions

      remote_guido = Fog::Bouncer::RemoteGroup.for('guido', @doorlist)
      source = remote_guido.sources.first
      source.user_alias.must_equal "jersey_shore"
      source.user_id.must_equal "1234567890"

      default = @fog.security_groups.get('default')
      default.ip_permissions.must_be_empty
    end
  end

  describe "#extras" do
    before do
      @group = Fog::Bouncer::RemoteGroup.from(@fog.security_groups.create(:name => "extra", :description => "Extra"), @doorlist)
      @default = Fog::Bouncer::RemoteGroup.from(@fog.security_groups.get('default'), @doorlist)
      @extras = @doorlist.extras
    end

    it "detects the extra groups" do
      @extras.must_equal [@default, @group]
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
      cloned_douchebag = @douchebag.clone([source])
      @doorlist.missing.must_equal [cloned_douchebag, @guido]
    end
  end
end
