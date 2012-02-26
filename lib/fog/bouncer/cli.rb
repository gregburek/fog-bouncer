require "clamp"

require "fog/bouncer"

module Fog
  module Bouncer
    module CLI
      def self.run(*a)
        MainCommand.run(*a)
      end

      class AbstractCommand < Clamp::Command
        option "--version", :flag, "show version" do
          puts "fog-bounder #{Fog::Bouncer::VERSION}"
          exit 0
        end
      end

      class MainCommand < AbstractCommand
      end
    end
  end
end
