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
          begin
            group.destroy
          rescue Fog::Compute::AWS::Error => exception
            unless exception.message =~ /InvalidGroup.InUse/
              raise
            end
            log group_in_use: true, group_name: group.name
          end
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
            begin
              group.destroy
            rescue Fog::Compute::AWS::Error => exception
              unless exception.message =~ /InvalidGroup.InUse/
                raise
              end
              log group_in_use: true, group_name: group.name
            end
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
