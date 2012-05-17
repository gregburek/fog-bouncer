require "fog/bouncer/source"
require "ipaddress"

module Fog
  module Bouncer
    module Sources
      def self.for(source, group, &block)
        begin
          CIDR.new(source, group, &block)
        rescue ArgumentError => e
          if e.message =~ /Invalid IP/
            Group.new(source, group, &block)
          else
            raise e
          end
        end
      end

      class CIDR < Fog::Bouncer::Source
        attr_reader :ip

        def initialize(source, group, &block)
          @ip = IPAddress::IPv4.new(source)
          source = @ip.to_string
          super
        end

        def match(source)
          range == source
        end

        def range
          @source
        end
      end

      class Group < Fog::Bouncer::Source
        attr_reader :name, :user_alias, :user_id

        def initialize(source, group, &block)
          super
          case source
          when /^(.+)@(.+)$/
            @name = $1
            @user_alias = $2
            if @user_alias[/^\d+$/]
              @user_id = @user_alias
              if account = group.security.accounts.find { |key, id| id == @user_id }
                @user_alias = account[0]
              end
            end
          else
            @name = source
            @user_alias = 'self'
          end
        end

        def match(source)
          "#{name}@#{user_id}" == source || "#{name}@#{user_alias}" == source || name == source
        end

        def user_id
          @user_id ||= group.security.accounts[user_alias]
        end
      end
    end
  end
end
