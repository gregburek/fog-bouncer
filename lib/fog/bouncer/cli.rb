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

        option ["--confirm"], "CONFIRMATION", "Confirm dangerous action", :attribute_name => :confirmation

        option ["--file", "-f"], "FILE", "Doorlist"

        option ["--groups", "-g"], "GROUPS", "Comma separated list of groups", :default => [] do |groups|
          Fog::Bouncer.specific_groups = groups.split(',')
        end

        option ["--pretend"], :flag, "Run in pretend mode" do
          Fog::Bouncer.pretend!
        end

        option "--version", :flag, "show version" do
          puts "fog-bouncer #{Fog::Bouncer::VERSION}"
          exit 0
        end

        def confirm
          unless confirmation
            puts
            puts " !    WARNING: This action is not marked as being safe."
            puts " !    To proceed, enter \"confirmation\" or re-run this command with --confirm confirmation"
            puts
            print "> "

            confirmation = $stdin.gets.chomp
          end

          confirmation == "confirmation" || raise("Confirmation failed")
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
