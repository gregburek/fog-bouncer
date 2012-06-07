require "helper"

describe Fog::Bouncer do
  before do
    Fog::Bouncer.reset
    Fog::Mock.reset if Fog.mocking?

    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]
    @doorlist.import_remote_groups
    @fog = Fog::Bouncer.fog
  end

  describe Fog::Bouncer::Source do
    describe "#extras" do
      before do
        @group = @doorlist.groups.first
        @group.sync
        @source = @group.sources.first
        @protocol = @source.protocols.first
        @protocol.local = false
        @protocol.remote = true
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
        @protocol.local = true
        @protocol.remote = false
        @group.sources << @source
        @missing = @source.missing
      end

      it "detects the missing protocols" do
        @missing.must_equal [@protocol]
      end
    end

    describe "ignoreable" do
      before do
        @group = @doorlist.groups.first
        @group.sync
        @source = Fog::Bouncer::Sources.for("4.4.4.4/1", @group)
        @source.protocols << Fog::Bouncer::Protocols::TCP.new(44, @source)
        @group.sources << @source
        @source.ignore = true
      end

      it "does not try to manage this source" do
        @source.local = false
        @source.remote = true
        @group.extra_remote_sources.wont_include @source

        @source.remote = false
        @source.local = true
        @group.missing_remote_sources.wont_include @source

        @group.sync

        @group.remote.ip_permissions.find { |perm| perm['ipProtocol'] == "tcp" && perm['fromPort'] == 90 }.must_be_nil
        @source.remote.must_equal false
      end
    end
  end
end
