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

  #describe Fog::Bouncer::Formatters::Diff do
    #describe ".format" do
      #it "sets returns the difference between local and remote" do
        #missing, extras = Fog::Bouncer::Formatters::Diff.format(@doorlist)

        #missing.must_equal @doorlist.groups.collect { |group| group.to_ip_permissions }
      #end
    #end
  #end
end
