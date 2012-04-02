require "fog"
require "fog/bouncer/group"
require "fog/bouncer/protocols"
require "fog/bouncer/security"
require "fog/bouncer/sources"
require "fog/bouncer/version"

require "fog/bouncer/ip_permissions"
require "fog/bouncer/group_manager"
require "fog/bouncer/source_manager"

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
  end
end
