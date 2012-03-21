require "clamp"

require "fog/bouncer"
require "fog/bouncer/cli/formatters"

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

      class DiffCommand < AbstractCommand
        option ["-d", "--doorlist"], "DOORLIST", "doorlist"

        def execute
          Fog::Bouncer::CLI::Formatters::Diff.format(doorlist)
        end
      end

      class MainCommand < AbstractCommand
        subcommand "diff", "Show difference", DiffCommand
      end
    end
  end
end
