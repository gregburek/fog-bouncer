require "helper"

describe Fog::Bouncer do
  before do
    @fog = Fog::Bouncer.fog
  end

  it "bounces" do
    true.must_equal true
  end

  describe "#security" do
    before do
      @doorlist = Fog::Bouncer.security do
        group "douchebag", "Don't let them in!" do
          source "1.1.1.1/1" do
            tcp 7070..8080
          end
        end
      end
    end

    it "has a douchebag group" do
      douchebag = @doorlist.groups.first
      douchebag.name.must_equal "douchebag"
      douchebag.description.must_equal "Don't let them in!"

      source = douchebag.sources.first
      source.must_be_kind_of Fog::Bouncer::CIDRSource
      source.range.must_equal "1.1.1.1/1"

      protocol = source.protocols[:tcp].first
      protocol.must_be_kind_of Fog::Bouncer::TCP
      protocol.from.must_equal 7070
      protocol.to.must_equal 8080
    end
  end
end
