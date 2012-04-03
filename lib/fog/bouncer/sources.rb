require "fog/bouncer/source"

module Fog
  module Bouncer
    module Sources
      def self.for(source, group, &block)
        if source =~ /^\d+\.\d+\.\d+.\d+\/\d+$/
          CIDR.new(source, group, &block)
        else
          Group.new(source, group, &block)
        end
      end

      class CIDR < Fog::Bouncer::Source
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
          "#{name}@#{user_id}" == source || name == source
        end

        def user_id
          @user_id ||= group.security.accounts[user_alias]
        end
      end
    end
  end
end
