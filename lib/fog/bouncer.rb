require "fog"
require "fog/bouncer/group"
require "fog/bouncer/protocols"
require "fog/bouncer/sources"
require "fog/bouncer/version"

module Fog
  module Bouncer
    def self.doorlists
      @doorlists ||= []
    end

    def self.fog
      @fog ||= Fog::Compute.new(
        :provider => "AWS",
        :region => (ENV['PROVIDER_REGION'] || 'us-east-1'),
        :aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
        :aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
      )
    end

    def self.security(&block)
      doorlists << Fog::Bouncer::Security.new(&block)
    end

    class Security
      def initialize(&block)
        instance_eval(&block)
      end

      def accounts
        @accounts ||= {}
      end

      def account(name, account_id)
        accounts[name] = account_id
      end

      def groups
        @groups ||= []
      end

      def group(name, description, &block)
        groups << LocalGroup.new(name, description, self, &block)
      end

      def sync
        groups.each do |group|
          group.sync
        end
      end
    end
  end
end
