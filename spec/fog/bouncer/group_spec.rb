require "helper"

describe Fog::Bouncer do
  before do
    Fog::Bouncer.reset
    Fog::Mock.reset if Fog.mocking?

    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]

    @fog = Fog::Bouncer.fog

    @group = @doorlist.groups.find { |g| g.name == 'douchebag' }
    @group.sync
  end

  describe Fog::Bouncer::Group do
    describe "#extras" do
      before do
        @group.from_ip_permissions([{ "ipProtocol" => "tcp", "fromPort" => 20, "toPort" => 20, "ipRanges" => [{ "cidrIp" => "2.2.2.2/2" }], "groups" => [] }])
      end

      it "detects the extra sources" do
        @group.extras.must_equal @group.sources.select { |s| s.source == "2.2.2.2/2" }
      end
    end

    describe "#missing" do
      before do
        @source = Fog::Bouncer::Sources.for("2.2.2.2/2", @group)
        @source.protocols << Fog::Bouncer::Protocols::TCP.new(90, @source)
        @group.sources << @source
      end

      it "detects the missing sources" do
        @group.missing.must_equal [@source]
      end
    end
  end
end
