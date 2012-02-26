module Fog
  module Bouncer
    class Source
      attr_reader :group

      def initialize(source, group, &block)
        @source = source
        @group = group
        instance_eval(&block) if block_given?
      end

      def protocols
        @protocols ||= { icmp: [], tcp: [], udp: [] }
      end

      def icmp(*ports)
        ports.each { |port| protocols[:icmp] << Fog::Bouncer::Protocols::ICMP.new(port, self) }
      end

      def tcp(*ports)
        ports.each { |port| protocols[:tcp] << Fog::Bouncer::Protocols::TCP.new(port, self) }
      end

      def udp(*ports)
        ports.each { |port| protocols[:udp] << Fog::Bouncer::Protocols::UDP.new(port, self) }
      end
    end

    module Sources
      def self.for(source, group, &block)
        if source =~ /^\d+\.\d+\.\d+.\d+\/\d+$/
          CIDR.new(source, group, &block)
        else
          Group.new(source, group, &block)
        end
      end

      class CIDR < Fog::Bouncer::Source
        def range
          @source
        end

        def sync
          protocols.each do |type, rules|
            rule.each do |rule|

            end
          end
        end
      end

      class Group < Fog::Bouncer::Source
        attr_reader :name, :user_alias, :user_id

        def initialize(source, group, &block)
          super
          case source
          when /^(.+)@(.+)$/
            @name = $1
            id_or_alias = $2
            if id_or_alias[/^\d+$/]
              @user_id = id_or_alias
              if account = group.security.accounts.find { |key, id| id == @user_id }
                @user_alias = account[0]
              end
            else
              @user_alias = id_or_alias
            end
          when /^@(.+)$/
            @user_alias = $1
          else
            @name = source
          end
        end

        def user_id
          @user_id ||= group.security.accounts[user_alias]
        end
      end
    end
  end
end
