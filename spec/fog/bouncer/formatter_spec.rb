require "helper"

describe Fog::Bouncer do
  before do
    load_security(:private)

    @doorlist = Fog::Bouncer.doorlists[:private]

    @fog = Fog::Bouncer.fog

    Fog::Mock.reset if Fog.mocking?
  end

  #describe Fog::Bouncer::Formatters::Diff do
    #describe ".format" do
      #it "sets returns the difference between local and remote" do
        #missing, extras = Fog::Bouncer::Formatters::Diff.format(@doorlist)

        #missing.must_equal @doorlist.groups.collect { |group| group.to_ip_permissions }
      #end
    #end
  #end
end
