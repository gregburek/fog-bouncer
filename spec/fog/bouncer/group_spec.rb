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
end
