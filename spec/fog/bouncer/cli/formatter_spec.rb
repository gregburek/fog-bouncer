require "helper"

require "fog/bouncer/cli"

describe Fog::Bouncer::CLI::Formatters::Diff do
  before do
    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]

    @fog = Fog::Bouncer.fog

    Fog::Mock.reset if Fog.mocking?
  end

  describe ".format" do
    it "sets returns the difference between local and remote" do
      Fog::Bouncer::CLI::Formatters::Diff.format(@doorlist).must_equal ""
    end
  end
end
