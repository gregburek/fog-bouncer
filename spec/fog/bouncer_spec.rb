require "helper"

describe Fog::Bouncer do
  before do
    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]

    @fog = Fog::Bouncer.fog

    Fog::Mock.reset if Fog.mocking?
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
      source.user_id.must_equal "1234567890"
      source.name.must_equal "douchebag"
    end
  end

  describe ".format" do
    it "sets the output format" do
      Fog::Bouncer.format = :diff
      Fog::Bouncer.format.must_equal :diff
      Fog::Bouncer.formatter.must_equal Fog::Bouncer::Formatters::Diff
    end
  end
end
