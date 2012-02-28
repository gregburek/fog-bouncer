require "helper"

describe Fog::Bouncer do
  before do
    load_security(:private)

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
