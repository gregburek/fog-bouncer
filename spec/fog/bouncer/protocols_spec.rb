require "helper"

describe Fog::Bouncer::Protocols::ICMP do
  subject { Fog::Bouncer::Protocols::ICMP }

  it "only supports valid AWS ICMP types" do
    lambda { subject.new(256, nil) }.must_raise(Fog::Bouncer::Protocols::InvalidICMPType)
  end
end

describe Fog::Bouncer::Protocols::TCP do
  subject { Fog::Bouncer::Protocols::TCP }

  it "only supports valid port ranges" do
    lambda { subject.new(65536, nil) }.must_raise(Fog::Bouncer::Protocols::InvalidPort)
  end
end

describe Fog::Bouncer::Protocols::UDP do
  subject { Fog::Bouncer::Protocols::UDP }

  it "only supports valid port ranges" do
    lambda { subject.new(65536, nil) }.must_raise(Fog::Bouncer::Protocols::InvalidPort)
  end
end
