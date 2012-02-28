require "helper"

describe Fog::Bouncer::Security do
  before do
    Fog::Bouncer.security :private do
      account "jersey_shore", "1234567890"

      group "douchebag", "Don't let them in!" do
        source "1.1.1.1/1" do
          tcp 7070..8080, 80
        end
      end

      group "guido", "Definitely don't let them in!" do
        source "douchebag@jersey_shore" do
          tcp 7070..8080
        end
      end
    end

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

      douchebag = @fog.security_groups.get('douchebag')
      Fog::Bouncer::RemoteGroup.for(douchebag.name, @doorlist).to_ip_permissions.must_equal @doorlist.groups.first.to_ip_permissions

      remote_guido = Fog::Bouncer::RemoteGroup.for('guido', @doorlist)
      source = remote_guido.sources.first
      source.user_alias.must_equal "jersey_shore"
      source.user_id.must_equal "1234567890"
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
