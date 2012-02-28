require "fog"
require "fog/bouncer/group"
require "fog/bouncer/protocols"
require "fog/bouncer/sources"
require "fog/bouncer/version"

module Fog
  module Bouncer
    def self.doorlists
      @doorlists ||= {}
    end

    def self.fog
      @fog ||= Fog::Compute.new(
        :provider => "AWS",
        :region => (ENV['PROVIDER_REGION'] || 'us-east-1'),
        :aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
        :aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
      )
    end

    def self.format
      @format || :json
    end

    def self.format=(format)
      @format = format
    end

    def self.formats
      @formats ||= {
        :diff => Fog::Bouncer::Formatters::Diff,
        :json => Fog::Bouncer::Formatters::JSON
      }
    end

    def self.formatter
      formats[format]
    end

    def self.load(file)
      if file && File.exists?(file)
        instance_eval(File.read(file))
      end
    end

    def self.security(name, &block)
      doorlists[name] = Fog::Bouncer::Security.new(name, &block)
    end

    class Security
      attr_reader :name

      def initialize(name, &block)
        @name = name
        instance_eval(&block)
      end

      def accounts
        @accounts ||= {}
      end

      def extras
        extras = []

        remote_groups.each do |group|
          if g = groups.find { |g| g.name == group.name }
            extras << g.clone(g.extras) if g.extras?
          else
            extras << group
          end
        end

        groups.each do |group|
          if group.remote && group.extras?
            extras << group.clone(group.extras)
          end
        end

        extras
      end

      def groups
        @groups ||= []
      end

      def missing
        missing = []

        groups.each do |group|
          if group.remote && group.missing?
            missing << group.clone(group.missing)
          elsif !group.remote
            missing << group
          end
        end

        missing
      end

      def remote_groups
        Fog::Bouncer.fog.security_groups.map { |group| RemoteGroup.from(group, self) }
      end

      def local_group(group)
        groups.find { |g| g.name == group.name }
      end

      def sync
        extras.each do |group|
          if local = local_group(group)
            local.destroy_extras
          else
            group.destroy
          end
        end

        missing.each do |group|
          group.create_missing
        end
      end

      private

      def account(name, account_id)
        accounts[name] = account_id
      end

      def group(name, description, &block)
        groups << LocalGroup.new(name, description, self, &block)
      end
    end

    class Formatter
    end

    module Formatters
      class Diff < Formatter
        def self.format(doorlist)
        end
      end

      class JSON < Formatter
      end
    end
  end
end
