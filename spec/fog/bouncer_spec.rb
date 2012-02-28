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

  describe ".security" do
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

  describe ".format" do
    it "sets the output format" do
      Fog::Bouncer.format = :diff
      Fog::Bouncer.format.must_equal :diff
      Fog::Bouncer.formatter.must_equal Fog::Bouncer::Formatters::Diff
    end
  end
end
