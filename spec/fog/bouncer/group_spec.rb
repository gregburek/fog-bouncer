require "helper"

describe Fog::Bouncer do
  before do
    Fog::Bouncer.reset
    Fog::Mock.reset if Fog.mocking?

    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]
    @fog = Fog::Bouncer.fog
    @doorlist.sync
  end

  describe Fog::Bouncer::Group do
    before do
      @group = @doorlist.groups.find { |g| g.name == 'douchebag' }
    end

    describe "#extras" do
      before do
        Fog::Bouncer::IPPermissions.to(@group, [{ "ipProtocol" => "tcp", "fromPort" => 20, "toPort" => 20, "ipRanges" => [{ "cidrIp" => "2.2.2.2/2" }], "groups" => [] }])

        @doorlist.clear_remote
      end

      it "detects the extra sources" do
        @group.extra_remote_sources.must_equal @group.sources.select { |s| s.source == "2.2.2.2/2" }

        @doorlist.clear_remote
      end
    end

    describe "#missing" do
      before do
        @source = Fog::Bouncer::Sources.for("2.2.2.2/2", @group)
        @source.protocols << Fog::Bouncer::Protocols::TCP.new(90, @source)
        @source.local = true
        @group.sources << @source
      end

      it "detects the missing sources" do
        @group.missing_remote_sources.must_equal [@source]

        @doorlist.clear_remote
      end
    end
  end
end
