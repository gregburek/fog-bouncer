require "clamp"

require "fog/bouncer"

module Fog
  module Bouncer
    module CLI
      def self.run(*a)
        MainCommand.run(*a)
      end

      class AbstractCommand < Clamp::Command
        option "--aws-account-id", "AWS_ACCOUNT_ID", "AWS Account ID" do |id|
          ENV['AWS_ACCOUNT_ID'] = id
        end
        option "--aws-access-key-id", "AWS_ACCESS_KEY_ID", "AWS Access Key ID" do |key|
          ENV['AWS_ACCESS_KEY_ID'] = key
        end
        option "--aws-secret-access-key", "AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key" do |key|
          ENV['AWS_SECRET_ACCESS_KEY'] = key
        end

        option ["--file", "-f"], "FILE", "Doorlist"

        option ["--groups", "-g"], "GROUPS", "Comma separated list of groups", :default => [] do |groups|
          groups.split(',')
        end

        option "--version", :flag, "show version" do
          puts "fog-bounder #{Fog::Bouncer::VERSION}"
          exit 0
        end

        def file
          if @file && File.exists?(File.expand_path(@file))
            File.expand_path(@file)
          elsif File.exists?(File.expand_path("Doorlist"))
            File.expand_path("Doorlist")
          else
            raise("Doorlist not found")
          end
        end
      end

      require "fog/bouncer/cli/diff"

      class MainCommand < AbstractCommand
        subcommand "diff", "Generate a diff between local and remote", DiffCommand
      end
    end
  end
end
