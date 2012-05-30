require "fog"
require "fog/bouncer/group"
require "fog/bouncer/protocols"
require "fog/bouncer/security"
require "fog/bouncer/sources"
require "fog/bouncer/version"

require "fog/bouncer/ip_permissions"
require "fog/bouncer/group_manager"
require "fog/bouncer/source_manager"

module Fog
  module Bouncer
    # Public: An AWS account ID
    #
    # Example
    #
    #   Fog::Bouncer.aws_account_id
    #   # => "1234567890"
    #
    # Returns a String
    def self.aws_account_id
      ENV['AWS_ACCOUNT_ID']
    end

    # Public: The available doorlists
    #
    # Example
    #
    #   Fog::Bouncer.doorlists
    #   # => { :doorlist => Fog::Bouncer::Security }
    #
    # Returns a Hash
    def self.doorlists
      @doorlists ||= {}
    end

    # Public: An establised fog AWS compute connection
    #
    # Example
    #
    #   Fog::Bouncer.fog
    #   # => Fog::AWS::Compute
    #
    # Returns a Fog::AWS::Compute object
    def self.fog
      @fog ||= Fog::Compute.new(
        :provider => "AWS",
        :region => (ENV['PROVIDER_REGION'] || 'us-east-1'),
        :aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
        :aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
      )
    end

    # Public: Allows the user to specify a logger for the log messages that Fog::Bouncer
    # produces.
    #
    # logger = The object you want logs to be sent too
    #
    # Examples
    #
    #   Fog::Bouncer.instrument_with(STDOUT.method(:puts))
    #   # => #<Method: IO#puts>
    #
    # Returns the logger object
    def self.instrument_with(logger)
      @logger = logger
    end

    # Internal: Top level log method for use by Fog::Bouncer
    #
    # data = Logging data (typically a hash)
    # blk  = block to execute
    #
    # Returns the response from calling the logger with the arguments
    def self.log(data, &blk)
      logger.call({ 'fog-bouncer' => true, 'pretending' => pretending? }.merge(data), &blk)
    end

    # Public: The logging location
    #
    # Returns an Object
    def self.logger
      @logger || STDOUT.method(:puts)
    end

    # Public: Load a file for evaluation
    #
    # Example
    #
    #   Fog::Bouncer.load('/tmp/doorlist.rb')
    #   # => Fog::Bouncer::Security
    #
    # Returns a Fog::Bouncer::Security object
    def self.load(file)
      if file && File.exists?(file)
        Fog::Bouncer.log(load: true, file: file) do
          instance_eval(File.read(file))
        end
      end
    end

    # Public: Check the pretend state
    #
    # Returns false or true if pretending
    def self.pretend
      @pretend ||= false
    end

    # Public: Pretend while evaluating the given block
    #
    # Example
    #
    #   Fog::Bouncer.while_pretending do
    #     ...
    #   end
    #
    # Returns nothing
    def self.while_pretending(&block)
      @pretend = true
      yield
      @pretend = false
    end

    # Public: Set the pretend state
    #
    # Returns the given state
    def self.pretend=(value)
      @pretend = value
    end

    # Public: Start pretending
    #
    # Returns true
    def self.pretend!
      @pretend = true
    end

    # Public: Evaluate the pretend state
    #
    # Returns true if pretending or false if not
    def self.pretending?
      !!pretend
    end

    # Public: Empty the doorlists
    # 
    # Returns an empty Hash
    def self.reset
      @doorlists = {}
    end

    # Public: Create a doorlist
    #
    # Example
    #
    #   Fog::Bouncer.security :private do
    #     group "name", "description" do
    #       ...
    #     end
    #   end
    #   # => Fog::Bouncer::Security
    #
    # Returns a Fog::Bouncer::Security object
    def self.security(name, &block)
      Fog::Bouncer.log(security: true, name: name) do
        doorlists[name] = Fog::Bouncer::Security.new(name, specific_groups, &block)
      end
    end

    def self.specific_groups
      @specific_groups ||= []
    end

    def self.specific_groups=(groups)
      @specific_groups = Array(groups)
    end
  end
end
