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

  it "bounces" do
    true.must_equal true
  end

  describe ".security" do
    it "has a douchebag group" do
      douchebag = @doorlist.groups.find { |g| g.name == 'douchebag' }
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
      source.user_id.must_equal ENV['AWS_ACCOUNT_ID']
      source.name.must_equal "douchebag"
    end
  end
end
