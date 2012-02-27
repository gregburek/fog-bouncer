require "helper"

describe Fog::Bouncer do
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

  it "bounces" do
    true.must_equal true
  end

  describe "#security" do
    it "has a douchebag group" do
      douchebag = @doorlist.groups.first
      douchebag.name.must_equal "douchebag"
      douchebag.description.must_equal "Don't let them in!"

      source = douchebag.sources.first
      source.must_be_kind_of Fog::Bouncer::Sources::CIDR
      source.range.must_equal "1.1.1.1/1"

      protocol = source.protocols.first
      protocol.must_be_kind_of Fog::Bouncer::Protocols::TCP
      protocol.from.must_equal 7070
      protocol.to.must_equal 8080
    end

    it "has a guido group" do
      guido = @doorlist.groups.find { |g| g.name == "guido" }

      source = guido.sources.first
      source.must_be_kind_of Fog::Bouncer::Sources::Group
      source.user_alias.must_equal "jersey_shore"
      source.user_id.must_equal "1234567890"
      source.name.must_equal "douchebag"
    end
  end

  describe Fog::Bouncer::Security do
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

  describe Fog::Bouncer::LocalGroup do
    describe "#extras" do
      before do
        @group = @doorlist.groups.first
        @group.sync
        @source = @group.sources.first
        @group.sources.delete_if { |source| source.source == @source.source }
        @extras = @doorlist.groups.first.extras
      end

      it "detects the extra sources" do
        @extras.must_equal [@source]
      end
    end

    describe "#missing" do
      before do
        @group = @doorlist.groups.first
        @group.sync
        @source = Fog::Bouncer::Sources.for("2.2.2.2/2", @group)
        @source.protocols << Fog::Bouncer::Protocols::TCP.new(90, @source)
        @group.sources << @source
        @missing = @doorlist.groups.first.missing
      end

      it "detects the missing sources" do
        @missing.must_equal [@source]
      end
    end
  end

  describe Fog::Bouncer::Source do
    describe "#extras" do
      before do
        @group = @doorlist.groups.first
        @group.sync
        @source = @group.sources.first
        @protocol = @source.protocols.first
        @source.protocols.delete_if { |protocol| protocol.from == @protocol.from }
        @extras = @source.extras
      end

      it "detects the extra protocols" do
        @extras.must_equal [@protocol]
      end
    end

    describe "#missing" do
      before do
        @group = @doorlist.groups.first
        @group.sync
        @source = Fog::Bouncer::Sources.for("1.1.1.1/1", @group)
        @source.protocols << (@protocol = Fog::Bouncer::Protocols::TCP.new(90, @source))
        @group.sources << @source
        @missing = @source.missing
      end

      it "detects the missing protocols" do
        @missing.must_equal [@protocol]
      end
    end
  end

  describe ".format" do
    it "sets the output format" do
      Fog::Bouncer.format = :diff
      Fog::Bouncer.format.must_equal :diff
      Fog::Bouncer.formatter.must_equal Fog::Bouncer::Formatters::Diff
    end
  end

  #describe Fog::Bouncer::Formatters::Diff do
    #describe ".format" do
      #it "sets returns the difference between local and remote" do
        #missing, extras = Fog::Bouncer::Formatters::Diff.format(@doorlist)

        #missing.must_equal @doorlist.groups.collect { |group| group.to_ip_permissions }
      #end
    #end
  #end
end
