module Fog
  module Bouncer
    class GroupManager
      def self.log(data, &block)
        Fog::Bouncer.log({group_manager: true}.merge(data), &block)
      end

      def log(data, &block)
        self.class.log(data, &block)
      end

      def initialize(security)
        @security = security
      end

      def synchronize
        log(synchronize: true) do
          create_missing_remote_groups
          synchronize_rules
          remove_extra_remote_groups
        end
      end

      def clear
        @security.groups.each do |group|
          group.revoke
        end

        @security.groups.each do |group|
          group.destroy
        end
      end

      private

      def create_missing_remote_groups
        @security.missing_remote_groups.each do |group|
          log(create_missing_remote_group: true, group_name: group.name) do
            group.create_missing_remote
          end
        end
      end

      def remove_extra_remote_groups
        @security.extra_remote_groups.each do |group|
          log(remove_extra_remote_group: true, group_name: group.name) do
            group.destroy
          end
        end
      end

      def synchronize_rules
        @security.groups.each do |group|
          log(synchronize_rules: true, group_name: group.name) do
            group.sync
          end
        end
      end
    end
  end
end
