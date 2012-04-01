require "fog"
require "fog/bouncer/group"
require "fog/bouncer/protocols"
require "fog/bouncer/sources"
require "fog/bouncer/version"

require "scrolls"

Scrolls::Log.start

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

    def self.log(data, &block)
      Scrolls.log({ 'fog-bouncer' => true }.merge(data), &block)
    end

    def self.load(file)
      if file && File.exists?(file)
        Fog::Bouncer.log(load: true, file: file) do
          instance_eval(File.read(file))
        end
      end
    end

    def self.reset
      @doorlists = {}
    end

    def self.security(name, &block)
      Fog::Bouncer.log(security: true, name: name) do
        doorlists[name] = Fog::Bouncer::Security.new(name, &block)
      end
    end

    class Security
      attr_reader :name, :description

      def initialize(name, &block)
        @name = name
        instance_eval(&block)
        groups_from_remote
      end

      def accounts
        @accounts ||= {}
      end

      def extras
        groups.select { |group| !group.local? || group.extras? }
      end

      def groups
        @groups ||= []
      end

      def missing
        groups.select { |group| !group.remote? || group.missing? }
      end

      def sync
        extras.each do |group|
          group.sync
        end

        missing.each do |group|
          group.sync
        end

        reset!
      end

      private

      def account(name, account_id)
        accounts[name] = account_id
      end

      def group(name, description, &block)
        group = groups.find { |group| group.name == name }
        group = Group.new(name, description, self, &block) if group.nil?
        groups << group
        group
      end

      def groups_from_remote
        Fog::Bouncer.fog.security_groups.each do |remote_group|
          group = groups.find { |group| group.name == remote_group.name }
          if group.nil?
            group = Group.new(remote_group.name, description, self)
            groups << group
          end

          group.remote = remote_group
          group.from_ip_permissions(remote_group.ip_permissions) if remote_group.ip_permissions
        end
      end
    end
  end
end
